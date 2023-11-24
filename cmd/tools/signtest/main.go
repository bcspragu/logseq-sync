// Command signtest is a quick tool for testing the generation and use of presigned S3 upload URLs.
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

func main() {
	accessKey := os.Args[1]
	secretKey := os.Args[2]
	sessionToken := os.Args[3]
	bucket := os.Args[4]
	prefix := os.Args[5]
	file := os.Args[6]

	sess, err := session.NewSession(&aws.Config{
		Credentials: credentials.NewStaticCredentials(accessKey, secretKey, sessionToken),
		Region:      aws.String("us-west-2"),
	})
	if err != nil {
		log.Fatalf("failed to init session from static creds: %v", err)
	}

	s3c := s3.New(sess)

	f, err := os.Open(file)
	if err != nil {
		log.Fatalf("failed to open named file: %v", err)
	}
	defer f.Close() // Best-effort

	fi, err := f.Stat()
	if err != nil {
		log.Fatalf("failed to stat file: %v", err)
	}

	fname := filepath.Base(file)

	key := filepath.Join(prefix, fname)
	s3Req, _ := s3c.PutObjectRequest(&s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	fmt.Printf("Signing URL for %s\n", key)

	urlStr, err := s3Req.Presign(5 * time.Minute)
	if err != nil {
		log.Fatalf("failed to presign upload URL: %v", err)
	}

	httpReq, err := http.NewRequest("PUT", urlStr, f)
	if err != nil {
		log.Fatalf("failed to format request: %v", err)
	}
	httpReq.ContentLength = fi.Size()

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		log.Fatalf("failed to upload file: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("unexpected status code %d", resp.StatusCode)
		dat, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("failed to read response body: %v", err)
		}
		log.Fatalf("Error body: \n%s\n", string(dat))
	}

	fmt.Println("Uploaded successfully!")
}
