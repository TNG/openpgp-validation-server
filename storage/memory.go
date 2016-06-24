package storage

import (
	"log"
)

// NewMemoryStore returns a GetSetDeleter that only stores values in memory
func NewMemoryStore() GetSetDeleter {
	log.Println("Using in-memory store: All data will be lost on service restart.")
	m := memoryStore{}
	m.store = map[[nonceLength]byte]*RequestInfo{}
	return &m
}

// memoryStore provides an in-memory GetSetDeleter
type memoryStore struct {
	store map[[nonceLength]byte]*RequestInfo
}

// Get returns the openpgp Entity saved under the given nonce
func (s *memoryStore) Get(nonce [nonceLength]byte) *RequestInfo {
	return s.store[nonce]
}

// Set persists the given openpgp Entity under the given nonce
func (s *memoryStore) Set(nonce [nonceLength]byte, requestor RequestInfo) {
	s.store[nonce] = &requestor
}

// Delete removes the given nonce from the list
func (s *memoryStore) Delete(nonce [nonceLength]byte) {
	delete(s.store, nonce)
}
