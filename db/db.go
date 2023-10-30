// Package db contains domain types for working with persisted Logseq data.
package db

import (
	"errors"
	"fmt"
	"time"
)

type GraphID string

type Tx int64

type GraphSalt struct {
	Value     []byte
	ExpiredAt time.Time
}

type GraphEncryptKey struct {
	EncryptedPrivateKey string
	PublicKey           string
}

type errAlreadyExists struct {
	entityName       string
	conflictingParam string
}

func (e errAlreadyExists) Error() string {
	return fmt.Sprintf("a %s with that %s already exists", e.entityName, e.conflictingParam)
}

func IsAlreadyExists(err error) bool {
	return errors.Is(err, errAlreadyExists{})
}

func AlreadyExists(name, param string) error {
	return errAlreadyExists{entityName: name, conflictingParam: param}
}

type errNotExists struct {
	entityName string
	id         string
}

func (e errNotExists) Error() string {
	return fmt.Sprintf("a %s with id %s doesn't exist", e.entityName, e.id)
}

func IsNotExists(err error) bool {
	return errors.Is(err, errNotExists{})
}

func NotExists[T ~string](name string, id T) error {
	return errNotExists{entityName: name, id: string(id)}
}
