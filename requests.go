package main

import (
	"bytes"
	"encoding/hex"
	"log"
	"os"
	"time"

	"github.com/TNG/gpg-validation-server/gpg"
	"github.com/TNG/gpg-validation-server/mail"
	"github.com/TNG/gpg-validation-server/smtp"
	"github.com/TNG/gpg-validation-server/storage"
	"github.com/TNG/gpg-validation-server/validator"
)

var serverGPG gpg.GPG

func serveSMTPRequestReceiver(host string, gpg gpg.GPG) {
	serverGPG = gpg
	smtpServer := smtp.NewServer(host, handleIncomingMail)
	smtpServer.Run()
}

func handleIncomingMail(incomingMail *smtp.MailEnvelope) {
	log.Printf("Incoming mail From: %v To: %v\n", incomingMail.From, incomingMail.To)
	result, err := validator.HandleMail(bytes.NewReader(incomingMail.Content), &serverGPG)
	if err != nil {
		log.Printf("Cannot handle mail: %s", err)
		return
	}

	log.Printf("Mail has valid signature: %v.\n", result.IsSigned())
	pubKey := result.GetPublicKey()

	for _, identity := range pubKey.Identities {
		log.Printf("Sending mail to %s", identity.UserId.Email)
		nonceSlice, _ := hex.DecodeString("32ff00000000000032ff00000000000032ff00000000000032ff000000000123")
		var nonce [32]byte
		copy(nonce[:], nonceSlice)

		store.Set(nonce, storage.RequestInfo{
			Key:       pubKey,
			Email:     identity.UserId.Email,
			Timestamp: time.Now(),
		})

		m := mail.OutgoingMail{
			Message:        hex.EncodeToString(nonce[:]),
			RecipientEmail: identity.UserId.Email,
			RecipientKey:   pubKey,
			Attachment:     []byte{},
			GPG:            &serverGPG,
		}
		b, err := m.Bytes()
		if err != nil {
			log.Printf("Error writing return email: %v\n", err)
			return
		}
		log.Println(string(b))
		file, err := os.Create("nonce.eml")
		if err != nil {
			log.Printf("Error writing return email: %v\n", err)
			return
		}
		defer func() { _ = file.Close() }()
		_, err = file.Write(b)
		if err != nil {
			log.Printf("Error writing return email: %v\n", err)
			return
		}
	}
}
