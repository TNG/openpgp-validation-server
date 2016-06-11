package storage

// NewMemoryStore returns a GetSetDeleter that only stores values in memory
func NewMemoryStore() GetSetDeleter {
	m := memoryStore{}
	m.store = map[[32]byte]*RequestInfo{}
	return &m
}

// memoryStore provides an in-memory GetSetDeleter
type memoryStore struct {
	store map[[32]byte]*RequestInfo
}

// Get returns the openpgp Entity saved under the given nonce
func (s *memoryStore) Get(nonce [32]byte) *RequestInfo {
	return s.store[nonce]
}

// Set persists the given openpgp Entity under the given nonce
func (s *memoryStore) Set(nonce [32]byte, requestor RequestInfo) {
	s.store[nonce] = &requestor
}

// Delete removes the given nonce from the list
func (s *memoryStore) Delete(nonce [32]byte) {
	delete(s.store, nonce)
}
