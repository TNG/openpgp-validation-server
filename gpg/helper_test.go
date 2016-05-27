package gpg

import (
	"bytes"
	"log"
	"os"
	"testing"

	"golang.org/x/crypto/openpgp"
)

func readEntityTest(t *testing.T, path string, armored bool, expectedKeys [2]bool, expectedIdentity string) {
	keyFile, err := os.Open(path)
	if err != nil {
		log.Fatal("Could not open test key file: ", err)
	}

	//entity, err := readEntity(keyFile, armored)
	entity, err := ReadKey(keyFile)
	if err != nil {
		t.Error("Failed to read entity:", err)
	}

	_, ok := entity.Identities[expectedIdentity]
	if !ok {
		t.Error("Could not find identity:", expectedIdentity)
	}

	if (entity.PrimaryKey != nil) != expectedKeys[0] {
		if expectedKeys[0] {
			t.Error("Expected public key, got none in:", path)
		} else {
			t.Error("Expected no public key, got one in:", path)
		}
	}

	if (entity.PrivateKey != nil) != expectedKeys[1] {
		if expectedKeys[0] {
			t.Error("Expected private key, got none in:", path)
		} else {
			t.Error("Expected no private key, got one in:", path)
		}
	}
}

func TestReadEntity(t *testing.T) {
	readEntityTest(t, binaryKeyFilePublic, false, [2]bool{true, false}, expectedIdentity)
	readEntityTest(t, binaryKeyFileSecret, false, [2]bool{true, true}, expectedIdentity)
}

func TestReadEntityArmored(t *testing.T) {
	readEntityTest(t, asciiKeyFilePublic, true, [2]bool{true, false}, expectedIdentity)
	readEntityTest(t, asciiKeyFileSecret, true, [2]bool{true, true}, expectedIdentity)

	readEntityTest(t, asciiKeyFileClient, true, [2]bool{true, false}, expectedClientIdentity)
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
	entity := readEntityFromFile(binaryKeyFileSecret, false)

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
	serverEntity := readEntityFromFile(binaryKeyFileSecret, false)

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
