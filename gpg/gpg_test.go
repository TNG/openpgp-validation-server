package gpg

import (
	"bytes"
	"testing"

	"github.com/TNG/gpg-validation-server/test/utils"
	"golang.org/x/crypto/openpgp"
)

func newGPGtest(t *testing.T, path string) {
	t.Log("Testing NewGPG for", path)

	file, cleanup := utils.Open(t, path)
	defer cleanup()

	gpg, err := NewGPG(file, passphrase)
	if err != nil {
		t.Fatal("Failed to create GPG object for", path, ":", err)
	}

	if gpg.serverEntity == nil {
		t.Error("Failed to initialize serverEntity for path:", path)
	}

	if _, ok := gpg.serverEntity.Identities[expectedIdentity]; !ok {
		t.Error("Could not find identity in serverEntity")
	}
}

func TestNewGPG(t *testing.T) {
	for _, path := range [2]string{asciiKeyFilePrivate, binaryKeyFilePrivate} {
		newGPGtest(t, path)
	}
}

func setupGPG(t *testing.T) *GPG {
	file, cleanup := utils.Open(t, asciiKeyFilePrivate)
	defer cleanup()

	gpg, err := NewGPG(file, passphrase)
	if err != nil {
		t.Fatal("Failed to create GPG object for", asciiKeyFilePrivate, ":", err)
	}
	return gpg
}

func TestGPGSignUserIDWithCorrectEmail(t *testing.T) {
	gpg := setupGPG(t)

	clientPublicKeyFile, cleanup := utils.Open(t, asciiKeyFileClient)
	defer cleanup()

	buffer := new(bytes.Buffer)
	err := gpg.SignUserID("test-gpg-validation@client.local", clientPublicKeyFile, buffer)
	if err != nil {
		t.Fatal("Failed to sign user id:", err)
	}

	signedClientEntity, _ := readEntity(buffer, true)
	verifySignatureTest(t, expectedClientIdentity, signedClientEntity)
}

func TestGPGSignUserIDWithIncorrectEmail(t *testing.T) {
	gpg := setupGPG(t)

	clientPublicKeyFile, cleanup := utils.Open(t, asciiKeyFileClient)
	defer cleanup()

	buffer := new(bytes.Buffer)
	err := gpg.SignUserID("impostor@faux.fake", clientPublicKeyFile, buffer)
	if err == nil {
		t.Fatal("Signed user id for fake email")
	}
}

func TestGPGSignMessage(t *testing.T) {
	gpg := setupGPG(t)
	messageString := []byte("Hello World!")

	message := bytes.NewReader(messageString)
	signature := new(bytes.Buffer)
	err := gpg.SignMessage(message, signature)
	if err != nil {
		t.Fatal("Signing message failed:", err)
	}

	keyFile, cleanup := utils.Open(t, binaryKeyFilePublic)
	defer cleanup()

	keyRing, err := openpgp.ReadKeyRing(keyFile)
	if err != nil {
		t.Fatal("Failed to read key ring:", err)
	}

	signer, err := openpgp.CheckArmoredDetachedSignature(keyRing, bytes.NewReader(messageString), signature)
	if err != nil {
		t.Error("Failed to verify signature:", err)
	}

	_, ok := signer.Identities[expectedIdentity]
	if !ok {
		t.Error("Signature not signed by", expectedIdentity)
	}
}
