package gpg

import (
	"bytes"
	"os"
	"testing"
)

func newGPGtest(t *testing.T, path string) {
	t.Log("Testing NewGPG for", path)
	file, _ := os.Open(path)
	defer file.Close()
	gpg, err := NewGPG(file, passphrase)
	if err != nil {
		t.Fatal("Failed to create GPG object for", path, ":", err)
	}

	if gpg.serverEntity == nil {
		t.Error("Failed to initialize serverEntity for path:", path)
	}
}

func TestNewGPG(t *testing.T) {
	for _, path := range [2]string{asciiKeyFilePrivate, binaryKeyFilePrivate} {
		newGPGtest(t, path)
	}
}

func setupGPG(t *testing.T) *GPG {
	file, _ := os.Open(asciiKeyFilePrivate)
	defer file.Close()
	gpg, err := NewGPG(file, passphrase)
	if err != nil {
		t.Fatal("Failed to create GPG object for", asciiKeyFilePrivate, ":", err)
	}
	return gpg
}

func TestGPGSignUserIDWithCorrectEmail(t *testing.T) {
	gpg := setupGPG(t)

	clientPublicKeyFile, _ := os.Open(asciiKeyFileClient)
	defer clientPublicKeyFile.Close()

	buffer := new(bytes.Buffer)
	err := gpg.SignUserID("test-gpg-validation@client.local", clientPublicKeyFile, buffer)
	if err != nil {
		t.Fatal("Failed to sign user id:", err)
	}

	signedClientEntity, _ := ReadEntity(buffer, true)
	verifySignatureTest(t, expectedClientIdentity, signedClientEntity)
}

func TestGPGSignUserIDWithIncorrectEmail(t *testing.T) {
	gpg := setupGPG(t)

	clientPublicKeyFile, _ := os.Open(asciiKeyFileClient)
	defer clientPublicKeyFile.Close()

	buffer := new(bytes.Buffer)
	err := gpg.SignUserID("impostor@faux.fake", clientPublicKeyFile, buffer)
	if err == nil {
		t.Fatal("Signed user id for fake email")
	}
}
