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
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/errors"
)

var testMessageBytes = []byte("Hello World!")

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
	clientPublicKey, err := readKey(clientPublicKeyFile)
	require.NoError(t, err)

	buffer := new(bytes.Buffer)
	err = gpg.SignUserID("test-gpg-validation@client.local", clientPublicKey, buffer)
	require.NoError(t, err, "Failed to sign user id")

	signedClientEntity, _ := readEntity(buffer, true)
	verifySignatureTest(t, expectedClientIdentity, signedClientEntity)
}

func TestGPGSignUserIDWithIncorrectEmail(t *testing.T) {
	gpg := setupGPG(t)

	clientPublicKeyFile, cleanup := utils.Open(t, asciiKeyFileClient)
	defer cleanup()
	clientPublicKey, err := readKey(clientPublicKeyFile)
	require.NoError(t, err)

	buffer := new(bytes.Buffer)
	err = gpg.SignUserID("impostor@faux.fake", clientPublicKey, buffer)
	if assert.Error(t, err, "Signing user id with fake email succeeded") {
		assert.Equal(t, ErrUnknownIdentity, err, "Unexpected error for signing user id with fake email", err.Error())
	}
}

func TestGPGSignUserIDWithInvalidKeyFile(t *testing.T) {
	gpg := setupGPG(t)

	buffer := new(bytes.Buffer)

	assert.Panics(t, func() { _ = gpg.SignUserID("test-gpg-validation@client.local", nil, buffer) })
}

func TestGPGSignMessage(t *testing.T) {
	gpg := setupGPG(t)

	message := bytes.NewReader(testMessageBytes)
	signature := new(bytes.Buffer)
	err := gpg.SignMessage(message, signature)
	require.NoError(t, err, "Signing message failed")

	keyFile, cleanup := utils.Open(t, binaryKeyFilePublic)
	defer cleanup()

	keyRing, err := openpgp.ReadKeyRing(keyFile)
	require.NoError(t, err, "Failed to read key ring")

	signer, err := openpgp.CheckArmoredDetachedSignature(keyRing, bytes.NewReader(testMessageBytes), signature)
	require.NoError(t, err, "Failed to verify signature")
	assert.Contains(t, signer.Identities, expectedIdentity, "Signature signed by wrong identity")
}

func TestGPGValidSignatureInExampleFiles(t *testing.T) {
	gpg := setupGPG(t)

	signerKeyFile, cleanup := utils.Open(t, asciiKeyFileClient)
	defer cleanup()
	signedText, cleanup := utils.Open(t, "../test/signatures/signed.txt")
	defer cleanup()
	signature, cleanup := utils.Open(t, "../test/signatures/signature.asc")
	defer cleanup()

	signerKey, err := readKey(signerKeyFile)
	require.NoError(t, err)

	err = gpg.CheckMessageSignature(signedText, signature, signerKey)
	assert.NoError(t, err, "Signature of test files should be valid.")
}

func checkMessageSignatureTest(t *testing.T, gpg *GPG, message, signature []byte, checkedSignerKeyFilePath string, expectedError error) {
	t.Log("Testing message signature against signer key:", checkedSignerKeyFilePath)
	signerKeyFile, cleanup := utils.Open(t, checkedSignerKeyFilePath)
	defer cleanup()
	signerKey, err := readKey(signerKeyFile)
	require.NoError(t, err)

	messageReader := bytes.NewReader(message)
	signatureReader := bytes.NewReader(signature)
	err = gpg.CheckMessageSignature(messageReader, signatureReader, signerKey)
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

	message := bytes.NewReader(testMessageBytes)
	signatureBuffer := new(bytes.Buffer)
	err := gpg.SignMessage(message, signatureBuffer)
	require.NoError(t, err, "Signing message failed")

	signatureBytes := signatureBuffer.Bytes()
	t.Log("Signature:", string(signatureBytes))

	checkMessageSignatureTest(t, gpg, testMessageBytes, signatureBytes, asciiKeyFilePublic, nil)
	checkMessageSignatureTest(t, gpg, testMessageBytes, signatureBytes, binaryKeyFilePublic, nil)

	// *KeyFileSecret contains both public and private key, so they can also be used to check the signature
	checkMessageSignatureTest(t, gpg, testMessageBytes, signatureBytes, asciiKeyFileSecret, nil)
	checkMessageSignatureTest(t, gpg, testMessageBytes, signatureBytes, binaryKeyFileSecret, nil)

	checkMessageSignatureTest(t, gpg, testMessageBytes, signatureBytes, asciiKeyFileClient, ErrUnknownIssuer)
	checkMessageSignatureTest(t, gpg, testMessageBytes, signatureBytes, binaryKeyFileClient, ErrUnknownIssuer)
	checkMessageSignatureTest(t, gpg, testMessageBytes, signatureBytes, asciiKeyFileOther, ErrUnknownIssuer)
}

func TestGPGEncryptMessage(t *testing.T) {
	gpg := setupGPG(t)

	cipherTextBuffer := new(bytes.Buffer)
	recipientKeyFile, cleanup := utils.Open(t, asciiKeyFileClient)
	defer cleanup()
	recipientKey, err := readKey(recipientKeyFile)
	require.NoError(t, err)

	writeCloser, err := gpg.EncryptMessage(cipherTextBuffer, recipientKey)
	assert.NoError(t, err)
	assert.NotNil(t, writeCloser)
	_, err = writeCloser.Write(testMessageBytes)
	assert.NoError(t, err)
	assert.NoError(t, writeCloser.Close())
	require.NoError(t, err, "Encryption failed")

	clientEntity := readEntityFromFile(asciiKeyFileClientSecret, true)
	serverPublicEntity := readEntityFromFile(asciiKeyFilePublic, true)
	err = decryptPrivateKeys(clientEntity, []byte(passphrase))
	require.NoError(t, err, "Failed to decrypt private keys")

	keyRing := openpgp.EntityList([]*openpgp.Entity{clientEntity, serverPublicEntity})

	block, err := armor.Decode(cipherTextBuffer)
	assert.NoError(t, err)
	md, err := openpgp.ReadMessage(block.Body, keyRing, nil, nil)
	require.NoError(t, err, "Decryption failed")
	assert.True(t, md.IsEncrypted, "Encrypted message has not actually been encrypted")
	assert.True(t, md.IsSigned, "Encrypted message has not been signed")

	decryptedMessageBytes, err := ioutil.ReadAll(md.UnverifiedBody)
	require.NoError(t, err, "Reading decrypted text failed")
	assert.Equal(t, string(testMessageBytes), string(decryptedMessageBytes), "Decrypted text does not match")
	if !assert.NoError(t, md.SignatureError, "Validating signature failed") {
		t.Log("Signature error:", md.SignatureError)
	}
	assert.Equal(t, gpg.serverEntity.PrimaryKey.KeyId, md.SignedByKeyId, "Message signed by wrong key")

	require.NotNil(t, md.SignedBy, "Signer key not found")
	assert.Contains(t, md.SignedBy.Entity.Identities, expectedIdentity, "Invalid signer key")
}

func TestGPGEncryptMessageWithInvalidRecipient(t *testing.T) {
	gpg := setupGPG(t)
	assert.NotNil(t, gpg)

	cipherTextBuffer := new(bytes.Buffer)

	assert.Panics(t, func() { _, _ = gpg.EncryptMessage(cipherTextBuffer, nil) })
}

func makeEncryptedMessage(t *testing.T, messageBytes []byte, signed bool) *bytes.Buffer {
	// Construct a message from client to server
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

	armorBuffer := new(bytes.Buffer)
	w, err = armor.Encode(armorBuffer, "ASCII ARMOR", map[string]string{})
	require.NoError(t, err)
	_, err = w.Write(cipherTextBuffer.Bytes())
	require.NoError(t, err)
	err = w.Close()
	require.NoError(t, err)
	return armorBuffer
}

func TestGPGDecryptSignedMessage(t *testing.T) {
	gpg := setupGPG(t)

	cipherTextBuffer := makeEncryptedMessage(t, testMessageBytes, true)
	decryptedTextBuffer := new(bytes.Buffer)
	senderKeyFile, cleanup := utils.Open(t, asciiKeyFileClient)
	defer cleanup()
	senderKey, err := readKey(senderKeyFile)
	require.NoError(t, err)

	err = gpg.DecryptSignedMessage(bytes.NewBuffer(cipherTextBuffer.Bytes()), decryptedTextBuffer, senderKey)
	require.NoError(t, err, "Decryption failed")
	assert.Equal(t, string(testMessageBytes), decryptedTextBuffer.String(), "Decrypted text does not match")
}

func decryptSignedMessageSignatureErrorTest(t *testing.T, signed bool, senderKeyFilePath string) error {
	gpg := setupGPG(t)

	cipherTextBuffer := makeEncryptedMessage(t, testMessageBytes, signed)
	decryptedTextBuffer := new(bytes.Buffer)
	senderKeyFile, cleanup := utils.Open(t, senderKeyFilePath)
	defer cleanup()
	senderKey, err := readKey(senderKeyFile)
	require.NoError(t, err)

	return gpg.DecryptSignedMessage(cipherTextBuffer, decryptedTextBuffer, senderKey)
}

func TestGPGDecryptSignedMessageWithUnsignedMessage(t *testing.T) {
	err := decryptSignedMessageSignatureErrorTest(t, false, asciiKeyFileClient)
	if assert.Error(t, err, "Decrypting unsigned succeeded") {
		assert.Equal(t, ErrMessageNotSigned, err, "Unexpected error for decrypting unsigned message", err.Error())
	}
}

func TestGPGDecryptSignedMessageWithWrongSigner(t *testing.T) {
	err := decryptSignedMessageSignatureErrorTest(t, true, asciiKeyFileOther)
	if assert.Error(t, err, "Decrypting message from wrong signer succeeded") {
		assert.Equal(t, ErrUnknownIssuer, err, "Unexpected error for decrypting message from wrong signer", err.Error())
	}
}

func TestGPGDecryptSignedMessageWithEmptyMessage(t *testing.T) {
	gpg := setupGPG(t)

	decryptedTextBuffer := new(bytes.Buffer)
	senderKeyFile, cleanup := utils.Open(t, asciiKeyFileClient)
	defer cleanup()
	senderKey, err := readKey(senderKeyFile)
	require.NoError(t, err)

	err = gpg.DecryptSignedMessage(new(bytes.Buffer), decryptedTextBuffer, senderKey)
	if assert.Error(t, err, "Decrypting empty message succeeded") {
		assert.Equal(t, io.EOF, err, "Unexpected error for decrypting empty message", err.Error())
	}
}

func TestGPGDecryptSignedMessageWithEmptySenderKey(t *testing.T) {
	gpg := setupGPG(t)

	cipherTextBuffer := makeEncryptedMessage(t, testMessageBytes, true)
	decryptedTextBuffer := new(bytes.Buffer)

	assert.Panics(t, func() { _ = gpg.DecryptSignedMessage(cipherTextBuffer, decryptedTextBuffer, nil) })
}
