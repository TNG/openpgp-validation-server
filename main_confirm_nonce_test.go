package main

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/TNG/openpgp-validation-server/gpg"
	"github.com/TNG/openpgp-validation-server/storage"
	"github.com/TNG/openpgp-validation-server/test/utils"
)

func TestConfirmNonce(t *testing.T) {
	store = storage.NewMemoryStore()
	nonceSlice, _ := hex.DecodeString("32ff00000000000032ff00000000000032ff00000000000032ff000000000123")
	var nonce [32]byte
	copy(nonce[:], nonceSlice)

	keyFile, cleanup := utils.Open(t, "test/keys/test-gpg-validation@other.local (0xF043F26E) pub.asc")
	defer cleanup()

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
