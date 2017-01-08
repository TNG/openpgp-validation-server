package mail

import (
	"testing"

	"github.com/TNG/openpgp-validation-server/gpg"
	"github.com/TNG/openpgp-validation-server/test/utils"
	"github.com/stretchr/testify/assert"
)

const prefix = "../test/keys/test-gpg-validation@server.local (0x87144E5E) "
const asciiKeyFilePublic = prefix + "pub.asc"
const asciiKeyFilePrivate = prefix + "sec.asc"
const passphrase = "validation"

func TestConstructCryptSignEmail(t *testing.T) {

	clientPublicKeyFile, cleanup := utils.Open(t, asciiKeyFilePublic)
	defer cleanup()

	serverPrivateKeyFile, cleanup := utils.Open(t, asciiKeyFilePrivate)
	defer cleanup()

	gpg, err := gpg.NewGPG(serverPrivateKeyFile, passphrase)
	assert.NoError(t, err)

	clientKey, err := gpg.ReadKey(clientPublicKeyFile)
	assert.NoError(t, err)

	m := OutgoingMail{"It works!", "test-gpg-validation@client.local", clientKey, []byte{}, gpg}
	b, err := m.Bytes()
	assert.NoError(t, err)
	t.Log(string(b))
}
