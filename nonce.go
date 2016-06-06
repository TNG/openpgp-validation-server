package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/TNG/gpg-validation-server/gpg"
	"github.com/TNG/gpg-validation-server/mail"
)

// NonceFromString parses and returns a nonce from a hex string
func NonceFromString(nonceString string) (nonce [32]byte, err error) {
	log.Println("NonceString: ", nonceString)
	nonceSlice, err := hex.DecodeString(nonceString)
	if err != nil {
		return
	}
	if len(nonceSlice) != 32 {
		err = errors.New(fmt.Sprint("Nonce has invalid length: ", len(nonceSlice)))
		return
	}
	copy(nonce[:], nonceSlice)
	return
}

func serveNonceConfirmer(address string) error {
	nonceChan := make(chan [32]byte)
	go func() {
		for {
			nonce := <-nonceChan
			err := ConfirmNonce(nonce)
			if err != nil {
				log.Println(err)
			}
		}
	}()
	http.HandleFunc("/confirm/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		nonce, err := NonceFromString(parts[2])
		if err == nil {
			nonceChan <- nonce
		} else {
			log.Println(err)
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	return http.ListenAndServe(address, nil)
}

// ConfirmNonce checks the given nonce, and if there is associated information, sends an email with the signed key
func ConfirmNonce(nonce [32]byte) error {
	fmt.Println(hex.EncodeToString(nonce[:]))
	requestInfo := store.Get(nonce)
	if requestInfo == nil {
		return errors.New("Nonce not found.")
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
