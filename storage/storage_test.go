package storage

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

var nonce0 = [32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
var nonce1 = [32]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

func testGetSetDeleter(t *testing.T, store GetSetDeleter) {
	m := NewMemoryStore()
	e1 := RequestInfo{}
	assert.Nil(t, m.Get(nonce0))
	assert.Nil(t, m.Get(nonce1))
	m.Set(nonce0, e1)
	e2 := m.Get(nonce0)
	require.Equal(t, e1, *e2, "Stored and retrieved entity should be equal")
	m.Delete(nonce0)
	assert.Nil(t, m.Get(nonce0))
}

func TestMemoryStore(t *testing.T) {
	m := NewMemoryStore()
	testGetSetDeleter(t, m)
}
