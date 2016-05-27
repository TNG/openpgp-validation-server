package gpg

import (
	"bytes"
	"io"
	"io/ioutil"
	"testing"

	"github.com/TNG/gpg-validation-server/test/utils"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/errors"
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
	for _, path := range [2]string{asciiKeyFileSecret, binaryKeyFileSecret} {
		newGPGtest(t, path)
	}

	file, cleanup := utils.Open(t, asciiKeyFileSecret)
	defer cleanup()
	_, err := NewGPG(file, "invalidpassphrase")
	if _, ok := err.(errors.StructuralError); !ok {
		t.Error("GPG object created with wrong passphrase")
	}

	file, cleanup = utils.Open(t, asciiKeyFilePublic)
	defer cleanup()
	_, err = NewGPG(file, passphrase)
	if err != ErrNoPrivateKey {
		t.Error("Unexpected error for GPG object creation without private key:", err)
	}

	invalidKeyFile := new(bytes.Buffer)
	_, err = NewGPG(invalidKeyFile, "")
	if err != io.EOF {
		t.Error("Unexpected error for GPG object creation from empty file:", err)
	}
}

func setupGPG(t *testing.T) *GPG {
	file, cleanup := utils.Open(t, asciiKeyFileSecret)
	defer cleanup()

	gpg, err := NewGPG(file, passphrase)
	if err != nil {
		t.Fatal("Failed to create GPG object for", asciiKeyFileSecret, ":", err)
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
	if err != ErrUnknownIdentity {
		t.Fatal("Unexpected error for signing user id with fake email:", err)
	}
}

func TestGPGSignUserIDWithInvalidKeyFile(t *testing.T) {
	gpg := setupGPG(t)

	buffer := new(bytes.Buffer)
	invalidKeyFile := new(bytes.Buffer)

	err := gpg.SignUserID("test-gpg-validation@client.local", invalidKeyFile, buffer)
	if err != io.EOF {
		t.Fatal("Unexpected error for signing invalid key file:", err)
	}
}

func TestGPGSignMessage(t *testing.T) {
	gpg := setupGPG(t)
	messageBytes := []byte("Hello World!")

	message := bytes.NewReader(messageBytes)
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

	signer, err := openpgp.CheckArmoredDetachedSignature(keyRing, bytes.NewReader(messageBytes), signature)
	if err != nil {
		t.Error("Failed to verify signature:", err)
	}

	_, ok := signer.Identities[expectedIdentity]
	if !ok {
		t.Error("Signature not signed by", expectedIdentity)
	}
}

func checkMessageSignatureTest(t *testing.T, gpg *GPG, message, signature []byte, checkedSignerKeyFilePath string, expectedError error) {
	signerKeyFile, cleanup := utils.Open(t, checkedSignerKeyFilePath)
	defer cleanup()

	messageReader := bytes.NewReader(message)
	signatureReader := bytes.NewReader(signature)
	err := gpg.CheckMessageSignature(messageReader, signatureReader, signerKeyFile)
	if err != expectedError {
		t.Error("Failed to correctly verify signature against key:", checkedSignerKeyFilePath)
		t.Error("Expected error:", expectedError)
		t.Error("Got error:", err)
	}
}

func TestGPGCheckMessageSignature(t *testing.T) {
	gpg := setupGPG(t)
	messageBytes := []byte("Hello World!")

	message := bytes.NewReader(messageBytes)
	signatureBuffer := new(bytes.Buffer)
	err := gpg.SignMessage(message, signatureBuffer)
	if err != nil {
		t.Fatal("Signing message failed:", err)
	}
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
	if err != nil {
		t.Fatal("Encryption failed:", err)
	}

	clientEntity := readEntityFromFile(asciiKeyFileClientSecret, true)
	serverPublicEntity := readEntityFromFile(asciiKeyFilePublic, true)
	decryptPrivateKeys(clientEntity, []byte(passphrase))
	keyRing := openpgp.EntityList([]*openpgp.Entity{clientEntity, serverPublicEntity})

	md, err := openpgp.ReadMessage(bytes.NewBuffer(cipherTextBuffer.Bytes()), keyRing, nil, nil)
	if err != nil {
		t.Fatal("Decryption failed:", err)
	}
	if !md.IsEncrypted {
		t.Error("Encrypted message has not actually been encrypted")
	}
	if !md.IsSigned {
		t.Error("Encrypted message has not been signed")
	}

	decryptedMessageBytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Fatal("Reading decrypted text failed:", err)
	}

	if string(decryptedMessageBytes) != string(messageBytes) {
		t.Error("Decrypted text mismatch")
		t.Error("Expected:", string(messageBytes))
		t.Error("Got:", string(decryptedMessageBytes))
	}

	if md.SignatureError != nil {
		t.Error("Validating signature failed:", md.SignatureError)
	}

	if md.SignedByKeyId != gpg.serverEntity.PrimaryKey.KeyId {
		t.Error("Message signed by wrong key")
		t.Error("Expected:", gpg.serverEntity.PrimaryKey.KeyId)
		t.Error("Got:", md.SignedByKeyId)
	}

	if md.SignedBy == nil {
		t.Error("Signer key not found")
	}

	if _, ok := md.SignedBy.Entity.Identities[expectedIdentity]; !ok {
		t.Error("Invalid signer key:", md.SignedBy)
	}
}

func TestGPGEncryptMessageWithInvalidRecipient(t *testing.T) {
	gpg := setupGPG(t)
	messageBytes := []byte("Hello World!")

	message := bytes.NewReader(messageBytes)
	cipherTextBuffer := new(bytes.Buffer)
	invalidRecipient := new(bytes.Buffer)

	err := gpg.EncryptMessage(message, cipherTextBuffer, invalidRecipient)
	if err != io.EOF {
		t.Fatal("Unexpected error for encrypting message to empty recipient key file:", err)
	}
}

func makeEncryptedMessage(t *testing.T, messageBytes []byte, signed bool) *bytes.Buffer {
	var senderEntity *openpgp.Entity

	recipientEntity := readEntityFromFile(asciiKeyFilePublic, true)
	if signed {
		senderEntity = readEntityFromFile(asciiKeyFileClientSecret, true)
		decryptPrivateKeys(senderEntity, []byte(passphrase))
	}

	cipherTextBuffer := new(bytes.Buffer)

	w, err := openpgp.Encrypt(cipherTextBuffer, []*openpgp.Entity{recipientEntity}, senderEntity, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(messageBytes)
	err = w.Close()
	if err != nil {
		t.Fatal(err)
	}

	return cipherTextBuffer
}

func TestGPGDecryptSignedMessage(t *testing.T) {
	gpg := setupGPG(t)
	messageBytes := []byte("Hello World!")

	cipherTextBuffer := makeEncryptedMessage(t, messageBytes, true)

	decryptedText := new(bytes.Buffer)
	senderKeyFile, cleanup := utils.Open(t, asciiKeyFileClient)
	defer cleanup()

	err := gpg.DecryptSignedMessage(bytes.NewBuffer(cipherTextBuffer.Bytes()), decryptedText, senderKeyFile)
	if err != nil {
		t.Fatal("Decryption failed:", err)
	}

	if decryptedText.String() != string(messageBytes) {
		t.Error("Decrypted text mismatch")
		t.Error("Expected:", string(messageBytes))
		t.Error("Got:", decryptedText.String())
	}
}

func TestGPGDecryptSignedMessageWithInvalidInput(t *testing.T) {
	gpg := setupGPG(t)
	messageBytes := []byte("Hello World!")

	cipherTextBuffer := makeEncryptedMessage(t, messageBytes, false)
	decryptedText := new(bytes.Buffer)
	senderKeyFile, cleanup := utils.Open(t, asciiKeyFileClient)
	defer cleanup()
	err := gpg.DecryptSignedMessage(bytes.NewBuffer(cipherTextBuffer.Bytes()), decryptedText, senderKeyFile)
	if err != ErrMessageNotSigned {
		t.Error("Unexpected error for decrypting unsigned message:", err)
	}

	cipherTextBuffer = makeEncryptedMessage(t, messageBytes, true)
	decryptedText = new(bytes.Buffer)
	senderKeyFile, cleanup = utils.Open(t, asciiKeyFileOther)
	defer cleanup()
	err = gpg.DecryptSignedMessage(bytes.NewBuffer(cipherTextBuffer.Bytes()), decryptedText, senderKeyFile)
	if err != ErrUnknownIssuer {
		t.Error("Unexpected error for decrypting message from wrong signer:", err)
	}

	senderKeyFile, cleanup = utils.Open(t, asciiKeyFileClient)
	defer cleanup()
	err = gpg.DecryptSignedMessage(new(bytes.Buffer), decryptedText, senderKeyFile)
	if err != io.EOF {
		t.Error("Unexpected error for decrypting empty message:", err)
	}

	err = gpg.DecryptSignedMessage(bytes.NewBuffer(cipherTextBuffer.Bytes()), decryptedText, new(bytes.Buffer))
	if err != io.EOF {
		t.Error("Unexpected error for decrypting message with empty sender key:", err)
	}
}
