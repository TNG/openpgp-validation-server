package mail

import (
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/TNG/gpg-validation-server/gpg"
)

const prefix = "../test-keys/test-gpg-validation@server.local (0x87144E5E) "
const asciiKeyFilePublic = prefix + "pub.asc"
const asciiKeyFilePrivate = prefix + "sec.asc"
const passphrase = "validation"

func TestConstructCryptSignEmail(t *testing.T) {

	clientPublicKeyFile, err := os.Open(asciiKeyFilePublic)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientPublicKeyFile.Close() }()
	clientKey, err := ioutil.ReadAll(clientPublicKeyFile)
	if err != nil {
		t.Fatal(err)
	}

	serverPrivateKeyFile, err := os.Open(asciiKeyFilePrivate)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = serverPrivateKeyFile.Close() }()
	gpg, err := gpg.NewGPG(serverPrivateKeyFile, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	m := OutgoingMail{"Content-Type: text/plain\n\nIt works!", "test-gpg-validation@client.local", clientKey, []byte{}, gpg}
	b := m.Bytes()
	log.Print(string(b))
}
