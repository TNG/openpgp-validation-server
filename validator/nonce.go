package validator

import (
	"crypto/rand"
)

// NonceLength in byte
const NonceLength = 32

func generateNonce() ([NonceLength]byte, error) {
	var nonce [NonceLength]byte

	n, err := rand.Read(nonce[:])
	if err != nil {
		return nonce, err
	}
	if n != NonceLength {
		panic("Unreachable")
	}

	return nonce, nil
}
