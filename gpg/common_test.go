package gpg

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/openpgp"
)

const expectedIdentity = "TEST gpg-validation-server (For Testing Only) <test-gpg-validation@server.local>"
const prefix = "../test/keys/test-gpg-validation@server.local (0x87144E5E) "
const asciiKeyFilePublic = prefix + "pub.asc"
const asciiKeyFileSecret = prefix + "sec.asc"
const binaryKeyFilePublic = prefix + "pub.asc.gpg"
const binaryKeyFileSecret = prefix + "sec.asc.gpg"
const passphrase = "validation"

const expectedClientIdentity = "TEST-client gpg-validation-server (For Testing Only) <test-gpg-validation@client.local>"
const prefixClient = "../test/keys/test-gpg-validation@client.local (0xE93B112A) "
const asciiKeyFileClient = prefixClient + "pub.asc"
const binaryKeyFileClient = prefixClient + "pub.asc.gpg"
const asciiKeyFileClientSecret = prefixClient + "sec.asc"

const prefixOther = "../test/keys/test-gpg-validation@other.local (0xF043F26E) "
const asciiKeyFileOther = prefixOther + "pub.asc"

func verifySignatureTest(t *testing.T, signedIdentity string, signedClientEntity *openpgp.Entity) {
	serverPublicEntity := readEntityFromFile(binaryKeyFilePublic, false)

	_, ok := signedClientEntity.Identities[signedIdentity]
	if !ok {
		t.Fatal("Signed entity does not have identity:", signedIdentity)
	}

	for index, signature := range signedClientEntity.Identities[signedIdentity].Signatures {
		err := serverPublicEntity.PrimaryKey.VerifyUserIdSignature(signedIdentity, signedClientEntity.PrimaryKey, signature)
		if err != nil {
			t.Error("Signature", index, "not valid:", err)
		}

		assert.Equal(t, uint32(15768000), *signature.SigLifetimeSecs, "Invalid signature expiry")
	}
}
