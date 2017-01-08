package storage

import (
	"time"

	"github.com/TNG/openpgp-validation-server/gpg"
)

const nonceLength = 32

// RequestInfo contains information on a signing request
type RequestInfo struct {
	Key       gpg.Key
	Email     string
	Timestamp time.Time
}

// GetSetDeleter provides a persistent map from []byte nonces to openpgp.Entities
type GetSetDeleter interface {
	Get(nonce [nonceLength]byte) *RequestInfo
	Set(nonce [nonceLength]byte, request RequestInfo)
	Delete(nonce [nonceLength]byte)
}
