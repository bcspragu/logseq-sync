// Command server will eventually feature a self-contained Logseq Sync service.
// Right now it mostly just records traffic to try to figure out what functionality
// we need to replicate.
package main

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	cryptorandrand "github.com/Silicon-Ally/cryptorand"
	"github.com/bcspragu/logseq-sync/blob"
	"github.com/bcspragu/logseq-sync/blob/awsblob"
	"github.com/bcspragu/logseq-sync/db"
	"github.com/bcspragu/logseq-sync/httperr"
	"github.com/bcspragu/logseq-sync/mem"
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

var reqSkip = map[string]bool{
	"accept":             true,
	"accept-language":    true,
	"user-agent":         true,
	"sec-ch-ua-platform": true,
	"sec-fetch-site":     true,
	"content-length":     true,
	"sec-ch-ua":          true,
	"sec-ch-ua-mobile":   true,
	"authorization":      true,
	"sec-fetch-mode":     true,
	"sec-fetch-dest":     true,
	"accept-encoding":    true,
}

type DB interface {
	IncrementTx(id db.GraphID) (db.Tx, error)
	Tx(id db.GraphID) (db.Tx, error)

	Graph(id db.GraphID) (string, error)
	CreateGraph(name string) (db.GraphID, db.Tx, error)

	AddGraphSalt(id db.GraphID, salt *db.GraphSalt) error
	GraphSalts(id db.GraphID) ([]*db.GraphSalt, error)

	AddGraphEncryptKeys(id db.GraphID, gek *db.GraphEncryptKey) error
	GraphEncryptKeys(id db.GraphID) ([]*db.GraphEncryptKey, error)
}

type Blob interface {
	GenerateTempCreds(ctx context.Context, prefix string) (*blob.Credentials, error)
}

type server struct {
	blob        Blob
	db          DB
	shouldProxy bool
	proxy       *httputil.ReverseProxy

	now func() time.Time

	r *rand.Rand
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("")
	}

	fs := flag.NewFlagSet(args[0], flag.ExitOnError)
	var (
		addr        = flag.String("addr", ":8000", "The address to host the sync server at")
		shouldProxy = flag.Bool("proxy", true, "Whether or not certain endpoints (like /user-info) should proxy data to the real API, or return fake data.")

		// Backend blob storage stuff
		s3Bucket  = flag.String("s3_bucket", "", "Name of the S3 bucket to hand out temp credentials for.")
		s3RoleARN = flag.String("s3_role_arn", "", "ARN of the role to grant temporary credentials for S3 bucket access from.")
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
		now: func() time.Time { return time.Now() },
		r:   cryptorandrand.New(),
	}
	mux.HandleFunc(
		"/get_files_meta",
		toHandleFunc[getFilesMetaRequest, getFilesMetaResponse](s.getFilesMeta),
	)
	mux.HandleFunc("/user_info", s.serveUserInfo)
	mux.HandleFunc(
		"/list_graphs",
		toHandleFunc[listGraphsRequest, listGraphsResponse](s.listGraphs),
	)
	mux.HandleFunc(
		"/create_graph",
		toHandleFunc[createGraphRequest, createGraphResponse](s.createGraph),
	)
	mux.HandleFunc(
		"/delete_graph",
		toHandleFunc[deleteGraphRequest, deleteGraphResponse](s.deleteGraph),
	)
	mux.HandleFunc(
		"/get_graph_encrypt_keys",
		toHandleFunc[getGraphEncryptKeysRequest, getGraphEncryptKeysResponse](s.getGraphEncryptKeys),
	)
	mux.HandleFunc(
		"/create_graph_salt",
		toHandleFunc[createGraphSaltRequest, createGraphSaltResponse](s.createGraphSalt),
	)
	mux.HandleFunc(
		"/get_graph_salt",
		toHandleFunc[getGraphSaltRequest, getGraphSaltResponse](s.getGraphSalt),
	)
	mux.HandleFunc(
		"/upload_graph_encrypt_keys",
		toHandleFunc[uploadGraphEncryptKeysRequest, uploadGraphEncryptKeysResponse](s.uploadGraphEncryptKeys),
	)
	mux.HandleFunc(
		"/get_all_files",
		toHandleFunc[getAllFilesRequest, getAllFilesResponse](s.getAllFiles),
	)
	mux.HandleFunc(
		"/get_txid",
		toHandleFunc[getTxidRequest, getTxidResponse](s.getTxid),
	)
	mux.HandleFunc(
		"/get_deletion_log_v20221212",
		toHandleFunc[getDeletionRequest, getDeletionResponse](s.getDeletionLog),
	)
	mux.HandleFunc(
		"/get_files",
		toHandleFunc[getFilesRequest, getFilesResponse](s.getFiles),
	)
	mux.HandleFunc(
		"/get_temp_credential",
		toHandleFunc[getTempCredentialRequest, getTempCredentialResponse](s.getTempCredential),
	)
	mux.HandleFunc(
		"/update_files",
		toHandleFunc[updateFilesRequest, updateFilesResponse](s.updateFiles),
	)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("\n=====\nReceived request %s: %s %s", r.Method, r.URL.Path, r.URL.RawQuery)
		// r.ParseForm()
		// log.Printf("Form data: %+v", r.Form)

		for k, vs := range r.Header {
			if reqSkip[strings.ToLower(k)] {
				continue
			}
			log.Printf("HEADER %q: %+v", k, vs)
		}

		dat, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("failed to read request body: %v", err)
			return
		}
		log.Printf("Request Body: %+v", string(dat))

		r.Body = io.NopCloser(bytes.NewReader(dat))

		ww := &ResponseWriter{ResponseWriter: w}
		s.proxy.ServeHTTP(ww, r)

		log.Printf("Response status: %d", ww.StatusCode)
		// for k, vs := range ww.Header() {
		// 	log.Printf("Response header %q: %+v", k, vs)
		// }
		log.Printf("Response body: %+v", ww.Buffer.String())
	})

	mux.HandleFunc("/file-sync", proxyWS)

	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1234),
		Subject: pkix.Name{
			Organization:  []string{"Test Org"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{},
			PostalCode:    []string{"12345"},
		},
		BasicConstraintsValid: true,
		IsCA:                  false,
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(1, 0, 0),
	}

	privateKey, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	publicKey := &privateKey.PublicKey
	certBytes, err := x509.CreateCertificate(cryptorand.Reader, cert, cert, publicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create x509 certificate: %w", err)
	}

	// Load TLS from certificate
	certPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	keyPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	tlsCert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return fmt.Errorf("failed to make key pair: %w", err)
	}

	handler := http.Server{
		Addr:    *addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		},
	}

	if err := handler.ListenAndServeTLS("", ""); err != nil {
		return fmt.Errorf("http.ListenAndServe: %w", err)
	}

	return nil
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
}

func (s *server) getFilesMeta(ctx context.Context, req *getFilesMetaRequest) (*getFilesMetaResponse, error) {
	return nil, errors.New("not implemented")
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
	return nil, errors.New("not implemented")
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
	return nil, errors.New("not implemented")
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

// TODO: Just 200, no response
type deleteGraphResponse struct{}

func (s *server) deleteGraph(ctx context.Context, req *deleteGraphRequest) (*deleteGraphResponse, error) {
	return nil, errors.New("not implemented")
}

type getGraphEncryptKeysRequest struct {
	GraphUUID string `json:"GraphUUID"`
}
type getGraphEncryptKeysResponse struct {
	PublicKey           string `json:"public-key"`
	EncryptedPrivateKey string `json:"encrypted-private-key"`
}

func (s *server) getGraphEncryptKeys(ctx context.Context, req *getGraphEncryptKeysRequest) (*getGraphEncryptKeysResponse, error) {
	return nil, errors.New("not implemented")
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

// TODO: Just 200, no response
type uploadGraphEncryptKeysResponse struct{}

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
	return nil, errors.New("not implemented")
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
	return nil, errors.New("not implemented")
}

type getFilesRequest struct {
	Files     []string `json:"Files"`
	GraphUUID string   `json:"GraphUUID"`
}
type getFilesResponse struct {
	PresignedFileURLs map[string]string `json:"PresignedFileURLs"`
}

func (s *server) getFiles(ctx context.Context, req *getFilesRequest) (*getFilesResponse, error) {
	return nil, errors.New("not implemented")
}

type getTempCredentialRequest struct{}
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
	return nil, errors.New("not implemented")
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
	return nil, errors.New("not implemented")
}

func toHandleFunc[Q any, S any](fn func(context.Context, *Q) (*S, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req Q
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		resp, err := fn(r.Context(), &req)
		if err != nil {
			handleError(w, err)
			return
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("failed to encode response: %v", err)
		}
	}
}
