// Command server will eventually feature a self-contained Logseq Sync service.
// Right now it mostly just records traffic to try to figure out what functionality
// we need to replicate.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	cryptorandrand "github.com/Silicon-Ally/cryptorand"
	"github.com/bcspragu/logseq-sync/blob"
	"github.com/bcspragu/logseq-sync/blob/awsblob"
	"github.com/bcspragu/logseq-sync/db"
	"github.com/bcspragu/logseq-sync/httperr"
	"github.com/bcspragu/logseq-sync/mem"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"nhooyr.io/websocket"
)

func main() {
	if err := run(os.Args); err != nil {
		log.Fatal(err)
	}
}

type ResponseWriter struct {
	http.ResponseWriter
	StatusCode int
	Buffer     bytes.Buffer
}

func (w *ResponseWriter) WriteHeader(status int) {
	w.StatusCode = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *ResponseWriter) Write(p []byte) (int, error) {
	w.Buffer.Write(p)
	return w.ResponseWriter.Write(p)
}

type DB interface {
	IncrementTx(id db.GraphID) (db.Tx, error)
	SetTx(id db.GraphID, tx db.Tx) error
	Tx(id db.GraphID) (db.Tx, error)

	Graph(id db.GraphID) (*db.Graph, error)
	Graphs() ([]*db.Graph, error)
	CreateGraph(name string) (db.GraphID, db.Tx, error)
	DeleteGraph(db.GraphID) error

	AddGraphSalt(id db.GraphID, salt *db.GraphSalt) error
	GraphSalts(id db.GraphID) ([]*db.GraphSalt, error)

	AddGraphEncryptKeys(id db.GraphID, gek *db.GraphEncryptKey) error
	GraphEncryptKeys(id db.GraphID) ([]*db.GraphEncryptKey, error)

	SetFileMeta(id db.GraphID, md *db.FileMeta) error

	// Because the Logseq client can/will request files it hasn't uploaded yet, the
	// map will contain nil entries for requested files that don't exist
	BatchFileMeta(id db.GraphID, fIDs []db.FileID) (map[db.FileID]*db.FileMeta, error)
	AllFileMeta(id db.GraphID) ([]*db.FileMeta, error)
}

type Blob interface {
	Bucket() string
	GenerateTempCreds(ctx context.Context, prefix string) (*blob.Credentials, error)
	Move(ctx context.Context, srcPath, destPath string) (*blob.MoveMeta, error)
	SignedDownloadURL(ctx context.Context, key string, dur time.Duration) (string, error)
}

type server struct {
	blob Blob

	db          DB
	shouldProxy bool
	proxy       *httputil.ReverseProxy

	now func() time.Time

	r   *rand.Rand
	jwt *jwt.Parser

	// TODO: Figure out how to handle this more elegantly
	region string
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("")
	}

	fs := flag.NewFlagSet(args[0], flag.ExitOnError)
	var (
		addr        = fs.String("addr", ":8000", "The address to host the sync server at")
		shouldProxy = fs.Bool("proxy", true, "Whether or not certain endpoints (like /user_info) should proxy data to the real API, or return fake data.")

		// Backend blob storage stuff
		s3Bucket  = fs.String("s3_bucket", "", "Name of the S3 bucket to hand out temp credentials for.")
		s3Region  = fs.String("s3_region", "us-west-2", "Name of the S3 region where AWS resources live")
		s3RoleARN = fs.String("s3_role_arn", "", "ARN of the role to grant temporary credentials for S3 bucket access from.")
	)
	if err := fs.Parse(args[1:]); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	mux := http.NewServeMux()

	// (def API-DOMAIN "api.logseq.com")
	apiTarget := &url.URL{
		Scheme: "https",
		Host:   "api.logseq.com",
	}

	awsBlob, err := awsblob.New(*s3Bucket, *s3RoleARN)
	if err != nil {
		return fmt.Errorf("failed to init AWS blob backend: %w", err)
	}

	s := server{
		blob:        awsBlob,
		db:          mem.New(),
		shouldProxy: *shouldProxy,
		proxy: &httputil.ReverseProxy{
			Rewrite: func(r *httputil.ProxyRequest) {
				r.SetURL(apiTarget)
			},
		},
		now:    func() time.Time { return time.Now() },
		r:      cryptorandrand.New(),
		jwt:    jwt.NewParser(),
		region: *s3Region,
	}
	mux.HandleFunc("/logseq/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Write([]byte("{}"))
	})
	mux.HandleFunc(
		"/file-sync/get_files_meta",
		toHandleFunc[getFilesMetaRequest, getFilesMetaResponse](s.getFilesMeta),
	)
	mux.HandleFunc("/file-sync/user_info", s.serveUserInfo)
	mux.HandleFunc(
		"/file-sync/list_graphs",
		toHandleFunc[listGraphsRequest, listGraphsResponse](s.listGraphs),
	)
	mux.HandleFunc(
		"/file-sync/create_graph",
		toHandleFunc[createGraphRequest, createGraphResponse](s.createGraph),
	)
	mux.HandleFunc(
		"/file-sync/delete_graph",
		toHandleFunc[deleteGraphRequest, deleteGraphResponse](s.deleteGraph),
	)
	mux.HandleFunc(
		"/file-sync/get_graph_encrypt_keys",
		toHandleFunc[getGraphEncryptKeysRequest, getGraphEncryptKeysResponse](s.getGraphEncryptKeys),
	)
	mux.HandleFunc(
		"/file-sync/create_graph_salt",
		toHandleFunc[createGraphSaltRequest, createGraphSaltResponse](s.createGraphSalt),
	)
	mux.HandleFunc(
		"/file-sync/get_graph_salt",
		toHandleFunc[getGraphSaltRequest, getGraphSaltResponse](s.getGraphSalt),
	)
	mux.HandleFunc(
		"/file-sync/upload_graph_encrypt_keys",
		toHandleFunc[uploadGraphEncryptKeysRequest, uploadGraphEncryptKeysResponse](s.uploadGraphEncryptKeys),
	)
	mux.HandleFunc(
		"/file-sync/get_all_files",
		toHandleFunc[getAllFilesRequest, getAllFilesResponse](s.getAllFiles),
	)
	mux.HandleFunc(
		"/file-sync/get_txid",
		toHandleFunc[getTxidRequest, getTxidResponse](s.getTxid),
	)
	mux.HandleFunc(
		"/file-sync/get_deletion_log_v20221212",
		toHandleFunc[getDeletionRequest, getDeletionResponse](s.getDeletionLog),
	)
	mux.HandleFunc(
		"/file-sync/get_files",
		toHandleFunc[getFilesRequest, getFilesResponse](s.getFiles),
	)
	mux.HandleFunc(
		"/file-sync/get_temp_credential",
		toHandleFunc[getTempCredentialRequest, getTempCredentialResponse](s.getTempCredential),
	)
	mux.HandleFunc(
		"/file-sync/update_files",
		toHandleFunc[updateFilesRequest, updateFilesResponse](s.updateFiles),
	)
	mux.HandleFunc("/file-sync", proxyWS)

	handler := http.Server{
		Addr:    *addr,
		Handler: mux,
	}

	log.Printf("Starting server on %s", *addr)
	if err := handler.ListenAndServe(); err != nil {
		return fmt.Errorf("http.ListenAndServe: %w", err)
	}

	return nil
}

type UserID string

type authContextKey struct{}

// NOTE: This will only work in handlers that use the toHandleFunc wrapper.
func (s *server) getUserID(ctx context.Context) (UserID, error) {
	authHdr, ok := ctx.Value(authContextKey{}).(string)
	if !ok {
		return "", errors.New("no auth in context, is middleware active on this handler?")
	}
	if authHdr == "" {
		return "", errors.New("no 'Authorization' header in request")
	}
	if !strings.HasPrefix(strings.ToLower(authHdr), "bearer ") {
		return "", errors.New("malformed 'Authorization' header had no 'Bearer ' prefix")
	}

	// NOTE: We use ParseUnverified here because it's easier and on a self-hosted,
	// single person system, we don't really care if it's signed correctly or not.
	// That said, one could totally get the public keys from AWS Cognito to actually
	// verify the JWT.
	claims := jwt.MapClaims{}
	_, _, err := s.jwt.ParseUnverified(authHdr[7:], claims)
	if err != nil {
		return "", fmt.Errorf("failed to parse JWT: %w", err)
	}

	sub, err := claims.GetSubject()
	if err != nil {
		return "", fmt.Errorf("failed to get 'sub' claim from JWT: %w", err)
	}

	return UserID(sub), nil
}

func proxyWS(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log.Printf("Received WS/file-sync request %s: %s %s", r.Method, r.URL.Path, r.URL.RawQuery)

	// Accept websocket connection from client
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
		OriginPatterns:     []string{"*"},
	})
	if err != nil {
		log.Printf("Failed to accept connection: %v", err)
		return
	}
	defer c.Close(websocket.StatusInternalError, "")

	// (def WS-URL "wss://ws.logseq.com/file-sync?graphuuid=%s")
	remote, _, err := websocket.Dial(ctx, "wss://ws.logseq.com/file-sync?graphuuid="+r.URL.Query().Get("graphuuid"), nil)
	if err != nil {
		log.Printf("Failed to connect to remote server: %v", err)
		return
	}
	defer remote.Close(websocket.StatusInternalError, "")

	// Bi-directional copying
	errorCh := make(chan error, 2)
	go func() {
		typ, rr, err := c.Reader(ctx)
		if err != nil {
			errorCh <- fmt.Errorf("failed to read from client: %w", err)
			return
		}
		dat, err := io.ReadAll(rr)
		if err != nil {
			errorCh <- fmt.Errorf("failed to read WS message body from client: %w", err)
			return
		}
		log.Printf("Received WS message from client: %+v", string(dat))
		if err := remote.Write(ctx, typ, dat); err != nil {
			errorCh <- fmt.Errorf("failed to write message to remote: %w", err)
			return
		}
	}()

	go func() {
		typ, rr, err := remote.Reader(ctx)
		if err != nil {
			errorCh <- fmt.Errorf("failed to read from backend: %w", err)
			return
		}
		dat, err := io.ReadAll(rr)
		if err != nil {
			errorCh <- fmt.Errorf("failed to read WS message body from backend: %w", err)
			return
		}
		log.Printf("Received WS message from backend: %+v", string(dat))
		if err := c.Write(ctx, typ, dat); err != nil {
			errorCh <- fmt.Errorf("failed to write message to client: %w", err)
			return
		}
	}()

	err = <-errorCh // wait for error from any direction

	log.Printf("Error when proxying connection: %v", err)

	// Cleanup the other connection
	if websocket.CloseStatus(err) == websocket.StatusNormalClosure {
		c.Close(websocket.StatusNormalClosure, "")
		remote.Close(websocket.StatusNormalClosure, "")
	} else {
		c.Close(websocket.StatusInternalError, "An error occurred")
		remote.Close(websocket.StatusInternalError, "An error occurred")
	}

}

func handleError(w http.ResponseWriter, err error) {
	code, userMsg := httperr.Extract(err)
	http.Error(w, userMsg, code)
	log.Printf("error from handler %d, %s: %v", code, userMsg, err)
}

type getFilesMetaRequest struct {
	Files     []string `json:"Files"`
	GraphUUID string   `json:"GraphUUID"`
}
type getFilesMetaResponse []getFilesMetaResponseSingle

type getFilesMetaResponseSingle struct {
	FilePath     string `json:"FilePath"`
	Checksum     string `json:"Checksum"`
	LastModified int64  `json:"LastModified"`
	Size         int64  `json:"Size"`
	Txid         int64  `json:"Txid"`

	Error string `json:"Error,omitempty"`
}

func (s *server) getFilesMeta(ctx context.Context, req *getFilesMetaRequest) (*getFilesMetaResponse, error) {
	var fIDs []db.FileID
	for _, f := range req.Files {
		// TODO: Consider validating these, not sure how reliable the `e.<hex data>` is
		// though, should dig into that a bit more.
		fIDs = append(fIDs, db.FileID(f))
	}

	gID := db.GraphID(req.GraphUUID)
	mds, err := s.db.BatchFileMeta(gID, fIDs)
	if err != nil {
		return nil, httperr.Internal("failed to load batch file meta: %w", err)
	}

	userID, err := s.getUserID(ctx)
	if err != nil {
		return nil, httperr.Unauthorized("failed to load user ID: %w", err)
	}

	out := []getFilesMetaResponseSingle{}
	for id, md := range mds {
		if md == nil {
			// Means the requested ID wasn't found
			out = append(out, getFilesMetaResponseSingle{
				FilePath: string(md.ID),
				Error:    fmt.Sprintf("not found %s/%s/%s", userID, gID, id),
			})
			continue
		}

		out = append(out, getFilesMetaResponseSingle{
			FilePath:     string(md.ID),
			Checksum:     string(md.Checksum),
			LastModified: md.LastModifiedAt.UnixMilli(),
			Size:         md.Size,
			Txid:         int64(md.LastModifiedTX),
		})
	}

	// This is a wonky thing to do, but the alternative is not using the handy-dandy
	// toHandleFunc helper
	resp := getFilesMetaResponse(out)
	return &resp, nil
}

type userInfoRequest struct{}
type userInfoResponse struct {
	ExpireTime      int64    `json:"ExpireTime"`
	UserGroups      []string `json:"UserGroups"`
	ProUser         bool     `json:"ProUser"`
	StorageLimit    int64    `json:"StorageLimit"`
	GraphCountLimit int64    `json:"GraphCountLimit"`

	// XXX: I don't actually know what the types of these fields are, just that they
	// were `null`. This may cause deserialization failures for some accounts.
	LemonRenewsAt *int64  `json:"LemonRenewsAt"`
	LemonEndsAt   *int64  `json:"LemonEndsAt"`
	LemonStatus   *string `json:"LemonStatus"`
}

func (s *server) serveUserInfo(w http.ResponseWriter, r *http.Request) {
	if s.shouldProxy {
		s.proxy.ServeHTTP(w, r)
		return
	}
	toHandleFunc[userInfoRequest, userInfoResponse](s.userInfo)(w, r)
}

func (s *server) userInfo(ctx context.Context, req *userInfoRequest) (*userInfoResponse, error) {
	// Just return some reasonable, fake response?
	return &userInfoResponse{
		ExpireTime: s.now().AddDate(0, 2, 0).Unix(), // Perpetually two months in the future
		UserGroups: []string{
			// NOTE: Consider making this configurable once we figure out what these groups
			// mean/what they do/if they're useful.
			"beta-tester",
		},
		ProUser:         true,
		StorageLimit:    2 << 32, // A few GB
		GraphCountLimit: 10,
		LemonRenewsAt:   nil,
		LemonEndsAt:     nil,
		LemonStatus:     nil,
	}, nil
}

type listGraphsRequest struct{}
type listGraphsResponse struct {
	Graphs []listGraphsResponseGraph `json:"Graphs"`
}

type listGraphsResponseGraph struct {
	GraphStorageLimit int64  `json:"GraphStorageLimit"`
	GraphName         string `json:"GraphName"`
	GraphUUID         string `json:"GraphUUID"`
	GraphStorageUsage int64  `json:"GraphStorageUsage"`
}

func (s *server) listGraphs(ctx context.Context, req *listGraphsRequest) (*listGraphsResponse, error) {
	graphs, err := s.db.Graphs()
	if err != nil {
		return nil, httperr.Internal("failed to load graphs: %w", err)
	}

	var out []listGraphsResponseGraph
	for _, g := range graphs {
		out = append(out, listGraphsResponseGraph{
			GraphStorageLimit: 2 << 32, // A few GB
			GraphName:         g.Name,
			GraphUUID:         string(g.ID),
			// TODO: There's a bunch of ways we could actually return this accurately if it
			// matters. In no particular order:
			//    1. We store this info in FileMeta.Size, we could just sum that up (maybe as a DB method for efficient SQL implementations)
			//    2. We could keep a running tally every time /update_files is called
			//      - Less good because of the potential to get out of sync.
			//    3. We could query our blob store for the aggregate size of everything under a prefix.
			GraphStorageUsage: 123456,
		})
	}
	return &listGraphsResponse{
		Graphs: out,
	}, nil
}

type createGraphRequest struct {
	GraphName string `json:"GraphName"`
}
type createGraphResponse struct {
	GraphUUID string `json:"GraphUUID"`
	Txid      int64  `json:"TXId"`
}

func (s *server) createGraph(ctx context.Context, req *createGraphRequest) (*createGraphResponse, error) {
	gID, curTx, err := s.db.CreateGraph(req.GraphName)
	if db.IsAlreadyExists(err) {
		return nil, httperr.
			Conflict("graph already exists: %w", err).
			WithMessage("a graph with that name already exists")
	} else if err != nil {
		return nil, httperr.Internal("failed to create graph: %w", err)
	}
	return &createGraphResponse{
		GraphUUID: string(gID),
		Txid:      int64(curTx),
	}, nil
}

type deleteGraphRequest struct {
	GraphUUID string `json:"GraphUUID"`
}

type deleteGraphResponse struct{}

func (*deleteGraphResponse) respond(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	// No body
}

func (s *server) deleteGraph(ctx context.Context, req *deleteGraphRequest) (*deleteGraphResponse, error) {
	gID := db.GraphID(req.GraphUUID)

	if err := s.db.DeleteGraph(gID); err != nil {
		return nil, httperr.Internal("failed to delete graph: %w", err)
	}

	return &deleteGraphResponse{}, nil
}

type getGraphEncryptKeysRequest struct {
	GraphUUID string `json:"GraphUUID"`
}
type getGraphEncryptKeysResponse struct {
	PublicKey           string `json:"public-key"`
	EncryptedPrivateKey string `json:"encrypted-private-key"`
}

func (s *server) getGraphEncryptKeys(ctx context.Context, req *getGraphEncryptKeysRequest) (*getGraphEncryptKeysResponse, error) {
	gID := db.GraphID(req.GraphUUID)

	keys, err := s.db.GraphEncryptKeys(gID)
	if err != nil {
		return nil, httperr.Internal("failed to get graph encrypt keys %w", err)
	}
	if len(keys) == 0 {
		return nil, httperr.NotFound("no graph encrypt keys for %q", gID)
	}

	// Get the last/latest key
	key := keys[len(keys)-1]

	return &getGraphEncryptKeysResponse{
		PublicKey:           key.PublicKey,
		EncryptedPrivateKey: key.EncryptedPrivateKey,
	}, nil
}

type createGraphSaltRequest struct {
	GraphUUID string `json:"GraphUUID"`
}
type createGraphSaltResponse struct {
	Value     string `json:"value"`
	ExpiredAt int64  `json:"expired-at"`
}

func (s *server) createGraphSalt(ctx context.Context, req *createGraphSaltRequest) (*createGraphSaltResponse, error) {
	_, err := s.db.Graph(db.GraphID(req.GraphUUID))
	if db.IsNotExists(err) {
		return nil, httperr.NotFound("graph %q wasn't found", req.GraphUUID)
	} else if err != nil {
		return nil, httperr.Internal("failed to load graph: %w", err)
	}

	b := make([]byte, 64)
	if n, err := s.r.Read(b); err != nil {
		return nil, httperr.Internal("failed to generate random bytes: %w", err)
	} else if n != 64 {
		return nil, httperr.Internal("expected to read 64 random bytes, read %d", n)
	}

	// Experimentally, these seem to expire about two months into the future?
	exp := s.now().AddDate(0, 2, 0)
	return &createGraphSaltResponse{
		Value:     base64.StdEncoding.EncodeToString(b),
		ExpiredAt: exp.UnixMilli(),
	}, nil
}

type getGraphSaltRequest struct {
	GraphUUID string `json:"GraphUUID"`
}
type getGraphSaltResponse struct {
	Value     string `json:"value"`
	ExpiredAt int64  `json:"expired-at"`
}

func (s *server) getGraphSalt(ctx context.Context, req *getGraphSaltRequest) (*getGraphSaltResponse, error) {
	salts, err := s.db.GraphSalts(db.GraphID(req.GraphUUID))
	if db.IsNotExists(err) {
		return nil, httperr.NotFound("graph %q wasn't found", req.GraphUUID)
	} else if err != nil {
		return nil, httperr.Internal("failed to load graph salts: %w", err)
	}
	if len(salts) == 0 {
		// This was observed in the original API
		return nil, httperr.Gone("no salts in graph %q", req.GraphUUID)
	}
	salt := salts[len(salts)-1]

	// XXX: The end salt is the latest, which maybe isn't a great assumption to bake into our DB API.
	return &getGraphSaltResponse{
		Value:     base64.StdEncoding.EncodeToString(salt.Value),
		ExpiredAt: salt.ExpiredAt.UnixMilli(),
	}, nil
}

type uploadGraphEncryptKeysRequest struct {
	EncryptedPrivateKey string `json:"encrypted-private-key"`
	GraphUUID           string `json:"GraphUUID"`
	PublicKey           string `json:"public-key"`
}

type uploadGraphEncryptKeysResponse struct{}

func (*uploadGraphEncryptKeysResponse) respond(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	// No body
}

func (s *server) uploadGraphEncryptKeys(ctx context.Context, req *uploadGraphEncryptKeysRequest) (*uploadGraphEncryptKeysResponse, error) {
	err := s.db.AddGraphEncryptKeys(db.GraphID(req.GraphUUID), &db.GraphEncryptKey{
		EncryptedPrivateKey: req.EncryptedPrivateKey,
		PublicKey:           req.PublicKey,
	})
	if db.IsNotExists(err) {
		return nil, httperr.NotFound("graph %q wasn't found", req.GraphUUID)
	} else if err != nil {
		return nil, httperr.Internal("failed to load graph salts: %w", err)
	}
	return &uploadGraphEncryptKeysResponse{}, nil
}

type getAllFilesRequest struct {
	GraphUUID string `json:"GraphUUID"`
}
type getAllFilesResponse struct {
	Objects               []getAllFilesResponseObject `json:"Objects"`
	NextContinuationToken string                      `json:"NextContinuationToken"`
}
type getAllFilesResponseObject struct {
	Key          string `json:"Key"`          // `: "<user uuid>/<graph uuid>/e.<35-bytes hex-encoded>",
	LastModified int64  `json:"LastModified"` // `: <unix ts millis>,
	Checksum     string `json:"checksum"`     // `: "<16-bytes hex-encoded>",
	Size         int64  `json:"Size"`         // `: <size in bytes>,
	Txid         int64  `json:"Txid"`         // `: <tx num>
}

func (s *server) getAllFiles(ctx context.Context, req *getAllFilesRequest) (*getAllFilesResponse, error) {
	gID := db.GraphID(req.GraphUUID)

	// TODO: We definitely want to actually use the built in pagination here, need to figure out how the real API does it (e.g. batch size, token format, etc)
	mds, err := s.db.AllFileMeta(gID)
	if err != nil {
		return nil, httperr.Internal("failed to load batch file meta: %w", err)
	}

	userID, err := s.getUserID(ctx)
	if err != nil {
		return nil, httperr.Unauthorized("failed to load user ID: %w", err)
	}

	out := []getAllFilesResponseObject{}
	for _, md := range mds {
		out = append(out, getAllFilesResponseObject{
			Key:          path.Join(string(userID), string(gID), string(md.ID)),
			Checksum:     string(md.Checksum),
			LastModified: md.LastModifiedAt.UnixMilli(),
			Size:         md.Size,
			Txid:         int64(md.LastModifiedTX),
		})
	}

	return &getAllFilesResponse{
		Objects:               out,
		NextContinuationToken: "", // TODO: See above
	}, nil
}

type getTxidRequest struct {
	GraphUUID string `json:"GraphUUID"`
}
type getTxidResponse struct {
	Txid int64 `json:"TXId"`
}

func (s *server) getTxid(ctx context.Context, req *getTxidRequest) (*getTxidResponse, error) {
	tx, err := s.db.Tx(db.GraphID(req.GraphUUID))
	if db.IsNotExists(err) {
		return nil, httperr.NotFound("graph %q wasn't found", req.GraphUUID)
	} else if err != nil {
		return nil, httperr.Internal("failed to load graph: %w", err)
	}
	return &getTxidResponse{
		Txid: int64(tx),
	}, nil
}

type getDeletionRequest struct {
	GraphUUID string `json:"GraphUUID"`
	FromTxid  int64  `json:"FromTXId"`
}
type getDeletionResponse struct {
	// XXX: I don't know what the type of transactions actually is, this is a placeholder
	Transactions []string `json:"Transactions"`
}

func (s *server) getDeletionLog(ctx context.Context, req *getDeletionRequest) (*getDeletionResponse, error) {
	// TODO: Figure out the actual format here
	return &getDeletionResponse{
		Transactions: []string{},
	}, nil
}

type getFilesRequest struct {
	Files     []string `json:"Files"`
	GraphUUID string   `json:"GraphUUID"`
}
type getFilesResponse struct {
	PresignedFileURLs map[string]string `json:"PresignedFileURLs"`
}

func (s *server) getFiles(ctx context.Context, req *getFilesRequest) (*getFilesResponse, error) {
	userID, err := s.getUserID(ctx)
	if err != nil {
		return nil, httperr.Unauthorized("failed to load user ID: %w", err)
	}

	gID := db.GraphID(req.GraphUUID)
	if _, err := s.db.Graph(gID); db.IsNotExists(err) {
		return nil, httperr.NotFound("graph %q wasn't found", req.GraphUUID)
	} else if err != nil {
		return nil, httperr.Internal("failed to load graph: %w", err)
	}

	out := make(map[string]string)
	// TODO: Consider checking to see if these are valid, though there's no harm in
	// signing a URL for a non-existent blob.
	for _, id := range req.Files {
		key := path.Join(string(userID), string(gID), id)
		signed, err := s.blob.SignedDownloadURL(ctx, key, 5*time.Minute)
		if err != nil {
			return nil, httperr.Internal("failed to sign URL: %w", err)
		}
		out[id] = signed
	}

	return &getFilesResponse{
		PresignedFileURLs: out,
	}, nil
}

type getTempCredentialRequest struct{}

// Just because it's otherwise hard to verify this will work as expected, and to
// prevent accidentally removing the parseRequest func below.
var _ requester = getTempCredentialRequest{}

func (getTempCredentialRequest) parseRequest(r *http.Request) error {
	// The expected request body is blank for this endpoint. Not `{}`, not `null`, just blank.
	return nil
}

type getTempCredentialResponse struct {
	Credentials *getTempCredentialResponseCredentials `json:"Credentials"`
	S3Prefix    string                                `json:"S3Prefix"`
}
type getTempCredentialResponseCredentials struct {
	AccessKeyid  string `json:"AccessKeyId"`
	Expiration   string `json:"Expiration"`
	SecretKey    string `json:"SecretKey"`
	SessionToken string `json:"SessionToken"`
}

func (s *server) getTempCredential(ctx context.Context, req *getTempCredentialRequest) (*getTempCredentialResponse, error) {
	prefix := fmt.Sprintf("temp/%s:%s", s.region, uuid.NewString())
	creds, err := s.blob.GenerateTempCreds(ctx, prefix)
	if err != nil {
		return nil, httperr.Internal("failed to generate temp creds: %w", err)
	}

	return &getTempCredentialResponse{
		Credentials: &getTempCredentialResponseCredentials{
			AccessKeyid:  creds.AccessKeyID,
			Expiration:   creds.Expiration.Format("2006-01-02T15:04:05Z"),
			SecretKey:    creds.SecretAccessKey,
			SessionToken: creds.SessionToken,
		},
		// <logseq bucket name>/temp/<region>:<server chosen UUID>
		S3Prefix: path.Join(s.blob.Bucket(), prefix),
	}, nil
}

type updateFilesRequest struct {
	// Files is a map from file ID to a tuple of [<some S3 location>, <checksum>]
	Files map[string][2]string `json:"Files"`

	GraphUUID string `json:"GraphUUID"`
	Txid      int64  `json:"TXId"`
}

type updateFilesResponse struct {
	TXId int64 `json:"TXId"`
	// XXX: I'm not sure about the type here
	UpdateFailedFiles map[string]string `json:"UpdateFailedFiles"`
	UpdateSuccFiles   []string          `json:"UpdateSuccFiles"`
}

func (s *server) updateFiles(ctx context.Context, req *updateFilesRequest) (*updateFilesResponse, error) {
	// Theoretically, the flow here is something like:
	// 1. User calls getTempCredentials and gets
	// 2. User PUTs some arbitrary number files to that location
	//    - This seems like an attack vector, but a short expiration should mitigate?
	// 3. User calls this endpoint, noting the files they uploaded (at random names) and their checksums
	// 4. Server (us! right here!) moves those files into their permanent locations

	gID := db.GraphID(req.GraphUUID)

	dbTxID, err := s.db.Tx(gID)
	if err != nil {
		return nil, httperr.Internal("failed to load TX: %w", err)
	}

	// This doesn't seem to actually be a part of the API, so it might be fine to
	// omit, but the real API does namespace things by user ID.
	userID, err := s.getUserID(ctx)
	if err != nil {
		return nil, httperr.Unauthorized("failed to load user ID: %w", err)
	}
	var successFiles []string
	for id, tup := range req.Files {
		srcPath, checksumStr := tup[0], tup[1]
		checksum, err := hex.DecodeString(checksumStr)
		if err != nil {
			return nil, httperr.BadRequest("checksum %q wasn't hex-encoded", checksumStr)
		}
		if n := len(checksum); n != 16 {
			return nil, httperr.BadRequest("checksum was %d bytes, expected 16 bytes", n)
		}
		dstPath := path.Join(string(userID), req.GraphUUID, id)
		moveMeta, err := s.blob.Move(ctx, srcPath, dstPath)
		if err != nil {
			return nil, httperr.Internal("failed to move temp file: %w", err)
		}
		if err := s.db.SetFileMeta(gID, &db.FileMeta{
			ID:             db.FileID(id),
			BlobPath:       path.Join(s.blob.Bucket(), dstPath),
			Checksum:       checksum,
			Size:           moveMeta.Size,
			LastModifiedAt: moveMeta.LastModified,
			// TODO: Figure out transactions more generally, the pattern wasn't obvious to me.
			LastModifiedTX: db.Tx(req.Txid),
		}); err != nil {
			return nil, httperr.Internal("failed to record file: %w", err)
		}
		successFiles = append(successFiles, dstPath)
	}

	curTX := max(req.Txid, int64(dbTxID)) + 1
	if err := s.db.SetTx(gID, db.Tx(curTX)); err != nil {
		return nil, httperr.Internal("failed to update tx: %w", err)
	}

	return &updateFilesResponse{
		TXId: curTX,
		// NOTE: Not sure in what case we'd want to use this. I guess maybe to only
		// _partially_ fail above instead of failing everything?
		UpdateFailedFiles: map[string]string{},
		UpdateSuccFiles:   successFiles,
	}, nil
}

func toHandleFunc[Q any, S any](fn func(context.Context, *Q) (*S, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.URL.Path)
		if r.Method != http.MethodPost {
			handleError(w, httperr.MethodNotAllowed("request to %q had invalid method", r.URL.Path))
			return
		}

		ctx := context.WithValue(r.Context(), authContextKey{}, r.Header.Get("Authorization"))

		var req Q
		var reqA any = req
		reqI, ok := reqA.(requester)
		if ok {
			// Implements custom request parsing, do that.
			if err := reqI.parseRequest(r); err != nil {
				handleError(w, httperr.BadRequest("failed to parse custom request: %w", err))
				return
			}
		} else {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				handleError(w, httperr.BadRequest("failed to decode request as JSON: %w", err))
				return
			}
		}

		resp, err := fn(ctx, &req)
		if err != nil {
			handleError(w, err)
			return
		}
		log.Println(r.URL.Path, "success")

		// If the type implements a custom responder, we should use that.
		var respA any = resp
		respI, ok := respA.(responder)
		if ok {
			respI.respond(w, r)
			return
		}

		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("failed to encode response: %v", err)
		}
	}
}

type requester interface {
	parseRequest(r *http.Request) error
}

type responder interface {
	respond(w http.ResponseWriter, r *http.Request)
}
