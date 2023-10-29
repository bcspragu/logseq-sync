// Command server will eventually feature a self-contained Logseq Sync service.
// Right now it mostly just records traffic to try to figure out what functionality
// we need to replicate.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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
