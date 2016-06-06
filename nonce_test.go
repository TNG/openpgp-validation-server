package main

import (
	"encoding/hex"
	"github.com/TNG/gpg-validation-server/gpg"
	"github.com/TNG/gpg-validation-server/storage"
	"os"
	"testing"
	"time"
)

func TestConfirmNonce(t *testing.T) {
	store = storage.NewMemoryStore()
	nonceSlice, _ := hex.DecodeString("32ff00000000000032ff00000000000032ff00000000000032ff000000000123")
	var nonce [32]byte
	copy(nonce[:], nonceSlice)

	path := "test/keys/test-gpg-validation@other.local (0xF043F26E) pub.asc"
	keyFile, err := os.Open(path)
	if err != nil {
		panic(err)
	}

	emptyGPG := gpg.GPG{}
	entity, err := emptyGPG.ReadKey(keyFile)
	if err != nil {
		panic(err)
	}

	store.Set(nonce, storage.RequestInfo{
		Key:       entity,
		Email:     "test-gpg-validation@client.local",
		Timestamp: time.Now(),
	})
}
