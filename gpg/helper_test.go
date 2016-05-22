package gpg

import (
	"bytes"
	"log"
	"os"
	"testing"

	"golang.org/x/crypto/openpgp"
)

func readEntityTest(t *testing.T, path string, armored bool) {
	keyFile, err := os.Open(path)
	if err != nil {
		log.Fatal("Could not open test key file: ", err)
	}

	entity, err := readEntity(keyFile, armored)
	if err != nil {
		t.Error("Failed to read entity:", err)
	}

	_, ok := entity.Identities[expectedIdentity]
	if !ok {
		t.Error("Could not find identity:", expectedIdentity)
	}

	if entity.PrimaryKey == nil && entity.PrivateKey == nil {
		t.Error("No keys found")
	}
}

func TestReadEntity(t *testing.T) {
	for _, path := range [2]string{binaryKeyFilePublic, binaryKeyFilePrivate} {
		readEntityTest(t, path, false)
	}
}

func TestReadEntityArmored(t *testing.T) {
	for _, path := range [2]string{asciiKeyFilePublic, asciiKeyFilePrivate} {
		readEntityTest(t, path, true)
	}
}

func readEntityFromFile(path string, armored bool) *openpgp.Entity {
	keyFile, err := os.Open(path)
	if err != nil {
		log.Fatal("Could not open test key file: ", err)
	}

	entity, err := readEntity(keyFile, armored)
	if err != nil {
		log.Fatal("Failed to read entity:", path)
	}
	return entity
}

func TestDecryptPrivateKeys(t *testing.T) {
	entity := readEntityFromFile(binaryKeyFilePrivate, false)

	err := decryptPrivateKeys(entity, []byte(passphrase))
	if err != nil {
		t.Fatal("Decryption failed:", err)
	}

	if entity.PrivateKey.Encrypted {
		t.Error("Private key still encrypted")
	}

	for _, subKey := range entity.Subkeys {
		if subKey.PrivateKey.Encrypted {
			t.Error("Private sub-key still encrypted")
		}
	}
}

func TestSignClientPublicKey(t *testing.T) {
	serverEntity := readEntityFromFile(binaryKeyFilePrivate, false)

	err := decryptPrivateKeys(serverEntity, []byte("validation"))

	clientEntity := readEntityFromFile(asciiKeyFileClient, true)

	if err != nil {
		t.Fatal("Failed to read entity:", err)
	}

	signedIdentity := expectedClientIdentity
	oldSigCount := len(clientEntity.Identities[signedIdentity].Signatures)

	buffer := new(bytes.Buffer)
	err = signClientPublicKey(clientEntity, signedIdentity, serverEntity, buffer)
	if err != nil {
		t.Fatal("Signing failed:", err)
	}

	signedClientEntity, err := readEntity(buffer, true)
	if err != nil {
		t.Fatal("Failed to read signed key:", err)
	}

	newSigCount := len(signedClientEntity.Identities[signedIdentity].Signatures)

	if oldSigCount >= newSigCount {
		t.Error("No new signatures found")
	}

	verifySignatureTest(t, signedIdentity, signedClientEntity)
}
