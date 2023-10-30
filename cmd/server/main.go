// Command server will eventually feature a self-contained Logseq Sync service.
// Right now it mostly just records traffic to try to figure out what functionality
// we need to replicate.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"nhooyr.io/websocket"
)

func main() {
	if err := run(); err != nil {
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

type server struct {
}

func run() error {
	mux := http.NewServeMux()

	// (def API-DOMAIN "api.logseq.com")
	apiTarget := &url.URL{
		Scheme: "https",
		Host:   "api.logseq.com",
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(apiTarget)
		},
	}

	s := server{}
	mux.HandleFunc(
		"/get_files_meta",
		toHandleFunc[getFilesMetaRequest, getFilesMetaResponse](s.getFilesMeta),
	)
	mux.HandleFunc(
		"/user_info",
		toHandleFunc[userInfoRequest, userInfoResponse](s.userInfo),
	)
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
		toHandleFunc[getDeletionRequest, getDeletionResponse](s.getDeletion),
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
		proxy.ServeHTTP(ww, r)

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

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	publicKey := &privateKey.PublicKey
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, publicKey, privateKey)
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
		Addr:    ":8000",
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
	// TODO: Maybe introspect error for more specific status codes.
	http.Error(w, "an error occurred", http.StatusInternalServerError)
	log.Printf("error from handler: %v", err)
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
	return nil, errors.New("not implemented")
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
	return nil, errors.New("not implemented")
}

type getGraphSaltRequest struct {
	GraphUUID string `json:"GraphUUID"`
}
type getGraphSaltResponse struct {
	Value     string `json:"value"`
	ExpiredAt int64  `json:"expired-at"`
}

func (s *server) getGraphSalt(ctx context.Context, req *getGraphSaltRequest) (*getGraphSaltResponse, error) {
	return nil, errors.New("not implemented")
}

type uploadGraphEncryptKeysRequest struct {
	EncryptedPrivateKey string `json:"encrypted-private-key"`
	GraphUUID           string `json:"GraphUUID"`
	PublicKey           string `json:"public-key"`
}

// TODO: Just 200, no response
type uploadGraphEncryptKeysResponse struct{}

func (s *server) uploadGraphEncryptKeys(ctx context.Context, req *uploadGraphEncryptKeysRequest) (*uploadGraphEncryptKeysResponse, error) {
	return nil, errors.New("not implemented")
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
	return nil, errors.New("not implemented")
}

type getDeletionRequest struct {
	GraphUUID string `json:"GraphUUID"`
	FromTxid  int64  `json:"FromTXId"`
}
type getDeletionResponse struct {
	// XXX: I don't know what the type of transactions actually is, this is a placeholder
	Transactions []string `json:"Transactions"`
}

func (s *server) getDeletion(ctx context.Context, req *getDeletionRequest) (*getDeletionResponse, error) {
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
