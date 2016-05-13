package gpg

import (
	"log"
	"os"
	"testing"
)

const asciiKeyFile = "../test-keys/new-MacGPG2/TEST gpg-validation-server (For Testing Only) test-gpg-validation@server.local (0x87144E5E) pub-sec.asc"
const binaryKeyFile = "../test-keys/new-MacGPG2/TEST gpg-validation-server (For Testing Only) test-gpg-validation@server.local (0x87144E5E) pub-sec.asc.gpg"
const expectedIdentity = "TEST gpg-validation-server (For Testing Only) <test-gpg-validation@server.local>"

func TestReadEntity(t *testing.T) {
	keyFile, err := os.Open(binaryKeyFile)
	if err != nil {
		log.Fatal("Could not open test key file: ", err)
	}

	entity, err := ReadEntity(keyFile, 0, false)
	if err != nil {
		t.Error("Failed to read entity:", err)
	}

    _, ok := entity.Identities[expectedIdentity]
    if ! ok {
        t.Error("Could not find identity:", expectedIdentity)
    }
}

func TestReadEntityArmored(t *testing.T) {
	keyFile, err := os.Open(asciiKeyFile)
	if err != nil {
		log.Fatal("Could not open test key file: ", err)
	}

	entity, err := ReadEntity(keyFile, 0, true)
	if err != nil {
		t.Error("Failed to read entity:", err)
	}

    _, ok := entity.Identities[expectedIdentity]
    if ! ok {
        t.Error("Could not find identity:", expectedIdentity)
    }
}