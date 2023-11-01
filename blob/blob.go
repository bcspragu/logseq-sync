// Package blob defines domain types for interacting with blob storage.
package blob

import "time"

type MoveMeta struct {
	LastModified time.Time
	Size         int64
}

type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}
