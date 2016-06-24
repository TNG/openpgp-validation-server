package validator

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"text/template"

	"github.com/TNG/gpg-validation-server/mail"
	"github.com/TNG/gpg-validation-server/storage"
)

var signedKeyMessage = template.Must(template.ParseFiles("./templates/signedKeyMail.tmpl"))

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
func ConfirmNonce(nonce [NonceLength]byte, store storage.GetSetDeleter, gpgUtil mail.GpgUtility) (*mail.OutgoingMail, error) {
	if gpgUtil == nil {
		return nil, fmt.Errorf("Skipping nonce confirmation, as gpgUtil is not available.")
	}

	if store == nil {
		return nil, fmt.Errorf("Skipping nonce confirmation, as store is not available.")
	}
	requestInfo := store.Get(nonce)

	if requestInfo == nil {
		return nil, fmt.Errorf("Cannot confirm nonce, %v not found.", hex.EncodeToString(nonce[:]))
	}

	log.Printf("Signing key %v of '%v'.", requestInfo.Key.PrimaryKey.KeyIdString(), requestInfo.Email)

	buf := bytes.Buffer{}
	err := gpgUtil.SignUserID(requestInfo.Email, requestInfo.Key, &buf)
	if err != nil {
		return nil, err
	}
	message := getSignedKeyMessage()

	mail := mail.OutgoingMail{
		Message:        message,
		RecipientEmail: requestInfo.Email,
		RecipientKey:   requestInfo.Key,
		Attachment:     buf.Bytes(),
		GPG:            gpgUtil,
	}

	return &mail, nil
}

func getSignedKeyMessage() string {
	message := new(bytes.Buffer)
	err := signedKeyMessage.Execute(message, struct{}{})
	if err != nil {
		log.Panicf("Cannot generate signed-key message: %v\n", err)
		return ""
	}

	return message.String()
}
