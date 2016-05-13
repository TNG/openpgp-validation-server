package gpg

import (
	"bytes"
	"log"
	"os"
	"testing"

	"golang.org/x/crypto/openpgp"
)

const expectedIdentity = "TEST gpg-validation-server (For Testing Only) <test-gpg-validation@server.local>"
const prefix = "../test-keys/new-MacGPG2/TEST gpg-validation-server (For Testing Only) test-gpg-validation@server.local (0x87144E5E) "
const asciiKeyFilePublic = prefix + "pub.asc"
const asciiKeyFilePrivate = prefix + "sec.asc"
const binaryKeyFilePublic = prefix + "pub.asc.gpg"
const binaryKeyFilePrivate = prefix + "sec.asc.gpg"

func TestReadEntity(t *testing.T) {
	for _, path := range [2]string{binaryKeyFilePublic, binaryKeyFilePrivate} {
		keyFile, err := os.Open(path)
		if err != nil {
			log.Fatal("Could not open test key file: ", err)
		}

		entity, err := ReadEntity(keyFile, false)
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
}

func TestReadEntityArmored(t *testing.T) {
	for _, path := range [2]string{asciiKeyFilePublic, asciiKeyFilePrivate} {
		keyFile, err := os.Open(path)
		if err != nil {
			log.Fatal("Could not open test key file: ", err)
		}

		entity, err := ReadEntity(keyFile, true)
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
}

func readEntityFromFile(path string, armored bool) *openpgp.Entity {
	keyFile, err := os.Open(path)
	if err != nil {
		log.Fatal("Could not open test key file: ", err)
	}

	entity, err := ReadEntity(keyFile, armored)
	if err != nil {
		log.Fatal("Failed to read entity:", path)
	}
	return entity
}

func TestDecryptPrivateKeys(t *testing.T) {
	entity := readEntityFromFile(binaryKeyFilePrivate, false)

	err := DecryptPrivateKeys(entity, []byte("validation"))
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

const prefixClient = "../test-keys/new-MacGPG2/TEST-client gpg-validation-server (For Testing Only) test-gpg-validation@client.local (0xE93B112A) "
const asciiKeyFileClient = prefixClient + "pub.asc"
const binaryKeyFileClient = prefixClient + "pub.asc.gpg"

func TestSignClientPublicKey(t *testing.T) {
	serverEntity := readEntityFromFile(binaryKeyFilePrivate, false)

	err := DecryptPrivateKeys(serverEntity, []byte("validation"))

	clientEntity := readEntityFromFile(asciiKeyFileClient, true)
	if err != nil {
		t.Fatal("Failed to read entity:", err)
	}

	signedIdentity := ""
	for signedIdentity = range clientEntity.Identities {
		break
	}
	oldSigCount := len(clientEntity.Identities[signedIdentity].Signatures)

	buffer := new(bytes.Buffer)
	err = SignClientPublicKey(clientEntity, signedIdentity, serverEntity, buffer)
	if err != nil {
		t.Fatal("Signing failed:", err)
	}

	signedClientEntity, err := ReadEntity(buffer, true)
	if err != nil {
		t.Fatal("Failed to read signed key:", err)
	}

	newSigCount := len(signedClientEntity.Identities[signedIdentity].Signatures)

	if oldSigCount >= newSigCount {
		t.Error("No new signatures found")
	}

	serverPublicEntity := readEntityFromFile(binaryKeyFilePublic, false)

	for index, signature := range signedClientEntity.Identities[signedIdentity].Signatures {
		err = serverPublicEntity.PrimaryKey.VerifyUserIdSignature(signedIdentity, signedClientEntity.PrimaryKey, signature)
		if err != nil {
			t.Error("Signature", index, "not valid:", err)
		}
	}
}
