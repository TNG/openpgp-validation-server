package gpg

import (
	"bytes"
	"io"
	"io/ioutil"
	"testing"

	"github.com/TNG/gpg-validation-server/test/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/errors"
)

func newGPGtest(t *testing.T, path string) {
	t.Log("Testing NewGPG for", path)

	file, cleanup := utils.Open(t, path)
	defer cleanup()

	gpg, err := NewGPG(file, passphrase)

	require.NoError(t, err, "Failed to create GPG object")
	assert.NotNil(t, gpg.serverEntity, "Failed to initialize serverEntity")
	assert.Contains(t, gpg.serverEntity.Identities, expectedIdentity, "Could not find identity in serverEntity")
}

func TestNewGPG(t *testing.T) {
	for _, path := range [2]string{asciiKeyFileSecret, binaryKeyFileSecret} {
		newGPGtest(t, path)
	}
}

func TestNewGPGErrorCases(t *testing.T) {
	file, cleanup := utils.Open(t, asciiKeyFileSecret)
	defer cleanup()
	_, err := NewGPG(file, "invalidpassphrase")
	if assert.Error(t, err, "GPG object created with wrong passphrase") {
		assert.IsType(t, errors.StructuralError(""), err, "Unexpected error type")
	}

	file, cleanup = utils.Open(t, asciiKeyFilePublic)
	defer cleanup()
	_, err = NewGPG(file, passphrase)
	if assert.Error(t, err, "GPG object created without private key") {
		assert.Equal(t, ErrNoPrivateKey, err, "Unexpected error for GPG object creation without private key", err.Error())
	}

	invalidKeyFile := new(bytes.Buffer)
	_, err = NewGPG(invalidKeyFile, "")
	if assert.Error(t, err, "GPG object created from empty key file") {
		assert.Equal(t, io.EOF, err, "Unexpected error from GPG oject creation from empty key file", err.Error())
	}
}

func setupGPG(t *testing.T) *GPG {
	t.Log("Creating GPG object from", asciiKeyFileSecret)
	file, cleanup := utils.Open(t, asciiKeyFileSecret)
	defer cleanup()

	gpg, err := NewGPG(file, passphrase)
	require.NoError(t, err, "Failed to create GPG object")
	return gpg
}

func TestGPGSignUserIDWithCorrectEmail(t *testing.T) {
	gpg := setupGPG(t)

	clientPublicKeyFile, cleanup := utils.Open(t, asciiKeyFileClient)
	defer cleanup()

	buffer := new(bytes.Buffer)
	err := gpg.SignUserID("test-gpg-validation@client.local", clientPublicKeyFile, buffer)
	require.NoError(t, err, "Failed to sign user id")

	signedClientEntity, _ := readEntity(buffer, true)
	verifySignatureTest(t, expectedClientIdentity, signedClientEntity)
}

func TestGPGSignUserIDWithIncorrectEmail(t *testing.T) {
	gpg := setupGPG(t)

	clientPublicKeyFile, cleanup := utils.Open(t, asciiKeyFileClient)
	defer cleanup()

	buffer := new(bytes.Buffer)
	err := gpg.SignUserID("impostor@faux.fake", clientPublicKeyFile, buffer)
	if assert.Error(t, err, "Signing user id with fake email succeeded") {
		assert.Equal(t, ErrUnknownIdentity, err, "Unexpected error for signing user id with fake email", err.Error())
	}
}

func TestGPGSignUserIDWithInvalidKeyFile(t *testing.T) {
	gpg := setupGPG(t)

	buffer := new(bytes.Buffer)
	invalidKeyFile := new(bytes.Buffer)

	err := gpg.SignUserID("test-gpg-validation@client.local", invalidKeyFile, buffer)
	if assert.Error(t, err, "Signing empty key file succeeded") {
		assert.Equal(t, io.EOF, err, "Unexpected error from signing empty key file", err.Error())
	}
}

func TestGPGSignMessage(t *testing.T) {
	gpg := setupGPG(t)
	messageBytes := []byte("Hello World!")

	message := bytes.NewReader(messageBytes)
	signature := new(bytes.Buffer)
	err := gpg.SignMessage(message, signature)
	require.NoError(t, err, "Signing message failed")

	keyFile, cleanup := utils.Open(t, binaryKeyFilePublic)
	defer cleanup()

	keyRing, err := openpgp.ReadKeyRing(keyFile)
	require.NoError(t, err, "Failed to read key ring")

	signer, err := openpgp.CheckArmoredDetachedSignature(keyRing, bytes.NewReader(messageBytes), signature)
	require.NoError(t, err, "Failed to verify signature")
	assert.Contains(t, signer.Identities, expectedIdentity, "Signature signed by wrong identity")
}

func checkMessageSignatureTest(t *testing.T, gpg *GPG, message, signature []byte, checkedSignerKeyFilePath string, expectedError error) {
	t.Log("Testing message signature against signer key:", checkedSignerKeyFilePath)
	signerKeyFile, cleanup := utils.Open(t, checkedSignerKeyFilePath)
	defer cleanup()

	messageReader := bytes.NewReader(message)
	signatureReader := bytes.NewReader(signature)
	err := gpg.CheckMessageSignature(messageReader, signatureReader, signerKeyFile)
	if expectedError == nil {
		assert.NoError(t, err, "Failed to correctly verify signature")
	} else {
		if assert.Error(t, err, "Expected error") {
			assert.Equal(t, expectedError, err, "Failed to correctly verify signature", err.Error())
		}
	}
}

func TestGPGCheckMessageSignature(t *testing.T) {
	gpg := setupGPG(t)
	messageBytes := []byte("Hello World!")

	message := bytes.NewReader(messageBytes)
	signatureBuffer := new(bytes.Buffer)
	err := gpg.SignMessage(message, signatureBuffer)
	require.NoError(t, err, "Signing message failed")

	signatureBytes := signatureBuffer.Bytes()
	t.Log("Signature:", string(signatureBytes))

	checkMessageSignatureTest(t, gpg, messageBytes, signatureBytes, asciiKeyFilePublic, nil)
	checkMessageSignatureTest(t, gpg, messageBytes, signatureBytes, binaryKeyFilePublic, nil)

	// *KeyFileSecret contains both public and private key, so they can also be used to check the signature
	checkMessageSignatureTest(t, gpg, messageBytes, signatureBytes, asciiKeyFileSecret, nil)
	checkMessageSignatureTest(t, gpg, messageBytes, signatureBytes, binaryKeyFileSecret, nil)

	checkMessageSignatureTest(t, gpg, messageBytes, signatureBytes, asciiKeyFileClient, ErrUnknownIssuer)
	checkMessageSignatureTest(t, gpg, messageBytes, signatureBytes, binaryKeyFileClient, ErrUnknownIssuer)
	checkMessageSignatureTest(t, gpg, messageBytes, signatureBytes, asciiKeyFileOther, ErrUnknownIssuer)
}

func TestGPGEncryptMessage(t *testing.T) {
	gpg := setupGPG(t)
	messageBytes := []byte("Hello World!")

	message := bytes.NewReader(messageBytes)
	cipherTextBuffer := new(bytes.Buffer)
	recipientKeyFile, cleanup := utils.Open(t, asciiKeyFileClient)
	defer cleanup()

	err := gpg.EncryptMessage(message, cipherTextBuffer, recipientKeyFile)
	require.NoError(t, err, "Encryption failed")

	clientEntity := readEntityFromFile(asciiKeyFileClientSecret, true)
	serverPublicEntity := readEntityFromFile(asciiKeyFilePublic, true)
	err = decryptPrivateKeys(clientEntity, []byte(passphrase))
	require.NoError(t, err, "Failed to decrypt private keys")

	keyRing := openpgp.EntityList([]*openpgp.Entity{clientEntity, serverPublicEntity})

	md, err := openpgp.ReadMessage(bytes.NewBuffer(cipherTextBuffer.Bytes()), keyRing, nil, nil)
	require.NoError(t, err, "Decryption failed")
	assert.True(t, md.IsEncrypted, "Encrypted message has not actually been encrypted")
	assert.True(t, md.IsSigned, "Encrypted message has not been signed")

	decryptedMessageBytes, err := ioutil.ReadAll(md.UnverifiedBody)
	require.NoError(t, err, "Reading decrypted text failed")
	assert.Equal(t, string(messageBytes), string(decryptedMessageBytes), "Decrypted text does not match")
	if !assert.Nil(t, md.SignatureError, "Validating signature failed") {
		t.Log("Signature error:", md.SignatureError)
	}
	assert.Equal(t, gpg.serverEntity.PrimaryKey.KeyId, md.SignedByKeyId, "Message signed by wrong key")

	require.NotNil(t, md.SignedBy, "Signer key not found")
	assert.Contains(t, md.SignedBy.Entity.Identities, expectedIdentity, "Invalid signer key")
}

func TestGPGEncryptMessageWithInvalidRecipient(t *testing.T) {
	gpg := setupGPG(t)
	messageBytes := []byte("Hello World!")

	message := bytes.NewReader(messageBytes)
	cipherTextBuffer := new(bytes.Buffer)
	invalidRecipient := new(bytes.Buffer)

	err := gpg.EncryptMessage(message, cipherTextBuffer, invalidRecipient)
	if assert.Error(t, err, "Encrypting message to empty recipient key file succeeded") {
		assert.Equal(t, io.EOF, err, "Unexpected error for encrypting message to empty recipient key file", err.Error())
	}
}

func makeEncryptedMessage(t *testing.T, messageBytes []byte, signed bool) *bytes.Buffer {
	var senderEntity *openpgp.Entity

	recipientEntity := readEntityFromFile(asciiKeyFilePublic, true)
	if signed {
		senderEntity = readEntityFromFile(asciiKeyFileClientSecret, true)
		err := decryptPrivateKeys(senderEntity, []byte(passphrase))
		require.NoError(t, err, "Failed to decrypt private keys")
	}

	cipherTextBuffer := new(bytes.Buffer)

	w, err := openpgp.Encrypt(cipherTextBuffer, []*openpgp.Entity{recipientEntity}, senderEntity, nil, nil)
	require.NoError(t, err)
	_, err = w.Write(messageBytes)
	require.NoError(t, err)
	err = w.Close()
	require.NoError(t, err)

	return cipherTextBuffer
}

func TestGPGDecryptSignedMessage(t *testing.T) {
	gpg := setupGPG(t)
	messageBytes := []byte("Hello World!")

	cipherTextBuffer := makeEncryptedMessage(t, messageBytes, true)

	decryptedTextBuffer := new(bytes.Buffer)
	senderKeyFile, cleanup := utils.Open(t, asciiKeyFileClient)
	defer cleanup()

	err := gpg.DecryptSignedMessage(bytes.NewBuffer(cipherTextBuffer.Bytes()), decryptedTextBuffer, senderKeyFile)
	require.NoError(t, err, "Decryption failed")
	assert.Equal(t, string(messageBytes), decryptedTextBuffer.String(), "Decrypted text does not match")
}

func TestGPGDecryptSignedMessageWithUnsignedMessage(t *testing.T) {
	gpg := setupGPG(t)
	messageBytes := []byte("Hello World!")

	cipherTextBuffer := makeEncryptedMessage(t, messageBytes, false)
	decryptedTextBuffer := new(bytes.Buffer)
	senderKeyFile, cleanup := utils.Open(t, asciiKeyFileClient)
	defer cleanup()
	err := gpg.DecryptSignedMessage(cipherTextBuffer, decryptedTextBuffer, senderKeyFile)
	if assert.Error(t, err, "Decrypting unsigned succeeded") {
		assert.Equal(t, ErrMessageNotSigned, err, "Unexpected error for decrypting unsigned message", err.Error())
	}
}

func TestGPGDecryptSignedMessageWithWrongSigner(t *testing.T) {
	gpg := setupGPG(t)
	messageBytes := []byte("Hello World!")

	cipherTextBuffer := makeEncryptedMessage(t, messageBytes, true)
	decryptedTextBuffer := new(bytes.Buffer)
	senderKeyFile, cleanup := utils.Open(t, asciiKeyFileOther)
	defer cleanup()
	err := gpg.DecryptSignedMessage(cipherTextBuffer, decryptedTextBuffer, senderKeyFile)
	if assert.Error(t, err, "Decrypting message from wrong signer succeeded") {
		assert.Equal(t, ErrUnknownIssuer, err, "Unexpected error for decrypting message from wrong signer", err.Error())
	}
}

func TestGPGDecryptSignedMessageWithEmptyMessage(t *testing.T) {
	gpg := setupGPG(t)

	decryptedTextBuffer := new(bytes.Buffer)
	senderKeyFile, cleanup := utils.Open(t, asciiKeyFileClient)
	defer cleanup()
	err := gpg.DecryptSignedMessage(new(bytes.Buffer), decryptedTextBuffer, senderKeyFile)
	if assert.Error(t, err, "Decrypting empty message succeeded") {
		assert.Equal(t, io.EOF, err, "Unexpected error for decrypting empty message", err.Error())
	}
}

func TestGPGDecryptSignedMessageWithEmptySenderKey(t *testing.T) {
	gpg := setupGPG(t)
	messageBytes := []byte("Hello World!")

	cipherTextBuffer := makeEncryptedMessage(t, messageBytes, true)

	decryptedTextBuffer := new(bytes.Buffer)
	err := gpg.DecryptSignedMessage(cipherTextBuffer, decryptedTextBuffer, new(bytes.Buffer))
	if assert.Error(t, err, "Decrypting message with empty sender key succeeded") {
		assert.Equal(t, io.EOF, err, "Unexpected error for decrypting message with empty sender key", err.Error())
	}
}
