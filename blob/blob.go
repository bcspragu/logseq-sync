// Package blob defines domain types for interacting with blob storage.
package blob

import "time"

type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}
