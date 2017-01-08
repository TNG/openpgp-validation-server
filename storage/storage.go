package storage

import (
	"fmt"
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

// StorageTypes contains all implemented storage types.
var StorageTypes = [...]string{
	"none",
	"memory",
	"file",
}

var storageConstructors = map[string](func() GetSetDeleter){
	StorageTypes[0]: NewNoneStore,
	StorageTypes[1]: NewMemoryStore,
	StorageTypes[2]: NewFileStore,
}

// NewStore returns a net GetSetDeleter that is backed by the specified storage.
func NewStore(storageType string) (GetSetDeleter, error) {
	constructor, ok := storageConstructors[storageType]

	if !ok {
		return nil, fmt.Errorf("Invalid storage type: '%s'", storageType)
	}

	return constructor(), nil
}
