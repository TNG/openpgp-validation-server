package validator

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/TNG/gpg-validation-server/gpg"
	"github.com/TNG/gpg-validation-server/mail"
	"github.com/TNG/gpg-validation-server/storage"
)

// NonceLength in byte
const NonceLength = 32

func generateNonce() ([NonceLength]byte, error) {
	var nonce [NonceLength]byte

	n, err := rand.Read(nonce[:])
	if err != nil {
		return nonce, err
	}
	if n != NonceLength {
		panic("Unreachable")
	}

	return nonce, nil
}

// NonceFromString parses and returns a nonce from a hex string
func NonceFromString(nonceString string) (nonce [NonceLength]byte, err error) {
	nonceSlice, err := hex.DecodeString(nonceString)
	if err != nil {
		return
	}
	if len(nonceSlice) != NonceLength {
		err = fmt.Errorf("Nonce has invalid length: %v", len(nonceSlice))
		return
	}
	copy(nonce[:], nonceSlice)
	return
}

// ConfirmNonce checks the given nonce, and if there is associated information, sends an email with the signed key
func ConfirmNonce(nonce [NonceLength]byte, store storage.GetSetDeleter) error {
	requestInfo := store.Get(nonce)

	if requestInfo == nil {
		return fmt.Errorf("Nonce %v not found.", hex.EncodeToString(nonce[:]))
	}

	log.Printf("Correct nonce received for Identity '%v' of Key %v.", requestInfo.Email, requestInfo.Key.PrimaryKey.KeyIdString())

	path := "test/keys/test-gpg-validation@server.local (0x87144E5E) sec.asc"
	keyFile, err := os.Open(path)
	if err != nil {
		return err
	}
	gpg, err := gpg.NewGPG(keyFile, "validation")
	if err != nil {
		return err
	}

	buf := bytes.Buffer{}
	err = gpg.SignUserID(requestInfo.Email, requestInfo.Key, &buf)
	if err != nil {
		return err
	}
	mail := mail.OutgoingMail{
		Message:        "Here is your signed key!",
		RecipientEmail: requestInfo.Email,
		RecipientKey:   requestInfo.Key,
		Attachment:     buf.Bytes(),
		GPG:            gpg,
	}
	mailBytes, err := mail.Bytes()
	if err != nil {
		return err
	}

	log.Println(string(mailBytes))
	file, err := os.Create("result.eml")
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	_, err = file.Write(mailBytes)
	return err
}
