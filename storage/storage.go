package storage

import (
	"time"

	"github.com/TNG/gpg-validation-server/gpg"
)

// RequestInfo contains information on a signing request
type RequestInfo struct {
	Key       gpg.Key
	Email     string
	Timestamp time.Time
}

// GetSetDeleter provides a persistent map from []byte nonces to openpgp.Entities
type GetSetDeleter interface {
	Get(nonce [32]byte) *RequestInfo
	Set(nonce [32]byte, request RequestInfo)
	Delete(nonce [32]byte)
}
