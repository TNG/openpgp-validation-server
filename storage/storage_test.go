package storage

import (
	"github.com/TNG/openpgp-validation-server/gpg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

var nonce0 = [32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
var nonce1 = [32]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

const asciiKeyFilePublic = "../test/keys/test-gpg-validation@server.local (0x87144E5E) pub.asc"

func testGetSetDeleter(t *testing.T, store GetSetDeleter) {
	f, err := os.Open(asciiKeyFilePublic)
	assert.Nil(t, err)
	data, err := ioutil.ReadAll(f)
	assert.Nil(t, err)
	key, err := gpg.UnmarshalKey(data)
	assert.Nil(t, err)
	e1 := RequestInfo{
		Email:     "test@localhost",
		Timestamp: time.Now(),
		Key:       key,
	}
	assert.Nil(t, store.Get(nonce0))
	assert.Nil(t, store.Get(nonce1))
	store.Set(nonce0, e1)
	e2 := store.Get(nonce0)
	require.Equal(t, e1.Email, e2.Email, "Stored and retrieved entity should be equal")
	require.Equal(t, e1.Timestamp.Unix(), e2.Timestamp.Unix(), "Stored and retrieved entity should be equal")
	require.Equal(t, e1.Key.PrimaryKey.KeyId, e2.Key.PrimaryKey.KeyId, "Stored and retrieved entity should be equal")
	store.Delete(nonce0)
	assert.Nil(t, store.Get(nonce0))
}

func TestMemoryStore(t *testing.T) {
	m := NewMemoryStore()
	testGetSetDeleter(t, m)
}

func TestFileStore(t *testing.T) {
	m := NewFileStore()
	testGetSetDeleter(t, m)
}
