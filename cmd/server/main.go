// Command server will eventually feature a self-contained Logseq Sync service.
// Right now it mostly just records traffic to try to figure out what functionality
// we need to replicate.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"time"

	"nhooyr.io/websocket"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received request %s: %s %s", r.Method, r.URL.Path, r.URL.RawQuery)
		r.ParseForm()
		log.Printf("Form data: %+v", r.Form)

		dat, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("failed to read request body: %v", err)
			return
		}
		log.Printf("Request Body: %+v", string(dat))
	})

	mux.HandleFunc("/file-sync", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received WS/file-sync request %s: %s %s", r.Method, r.URL.Path, r.URL.RawQuery)

		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			log.Printf("failed to upgrade HTTP request to websocket: %v", err)
		}
		defer c.CloseNow()

		for {
			typ, r, err := c.Reader(r.Context())
			if err != nil {
				log.Printf("failed to read websocket message: %v", err)
			}
			dat, err := io.ReadAll(r)
			if err != nil {
				log.Printf("failed to read data from websocket message: %v", err)
			}
			log.Printf("got message of type %q: %q", typ, hex.EncodeToString(dat))
		}
	})

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
