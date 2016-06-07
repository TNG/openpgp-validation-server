package main

import (
	"bytes"
	"encoding/hex"
	"io"
	"log"
	"os"
	"time"

	"github.com/TNG/gpg-validation-server/gpg"
	"github.com/TNG/gpg-validation-server/mail"
	"github.com/TNG/gpg-validation-server/smtp"
	"github.com/TNG/gpg-validation-server/storage"
	"github.com/TNG/gpg-validation-server/validator"
)

func serveSMTPRequestReceiver(host string, gpgUtil *gpg.GPG) {
	smtpServer := smtp.NewServer(host, getIncomingMailEnvelopeHandler(gpgUtil))
	smtpServer.Run()
}

func getIncomingMailEnvelopeHandler(gpgUtil *gpg.GPG) func(*smtp.MailEnvelope) {
	return func(incomingMail *smtp.MailEnvelope) {
		handleIncomingMailEnvelope(incomingMail, gpgUtil)
	}
}

func getIncomingMailHandler(gpgUtil *gpg.GPG) func(io.Reader) {
	return func(incomingMail io.Reader) {
		handleIncomingMail(incomingMail, gpgUtil)
	}
}

func handleIncomingMailEnvelope(incomingMail *smtp.MailEnvelope, gpgUtil *gpg.GPG) {
	log.Printf("Incoming mail From: %v To: %v\n", incomingMail.From, incomingMail.To)
	handleIncomingMail(bytes.NewReader(incomingMail.Content), gpgUtil)
}

func handleIncomingMail(incomingMail io.Reader, gpgUtil *gpg.GPG) {
	result, err := validator.HandleMail(incomingMail, gpgUtil)
	if err != nil {
		log.Printf("Cannot handle mail: %s", err)
		return
	}

	log.Printf("Mail has valid signature: %v.\n", result.IsSigned())

	if !result.IsSigned() {
		return
	}

	pubKey := result.GetPublicKey()

	for _, identity := range pubKey.Identities {
		log.Printf("Sending mail to %s", identity.UserId.Email)
		nonceSlice, _ := hex.DecodeString("32ff00000000000032ff00000000000032ff00000000000032ff000000000123")
		var nonce [32]byte
		copy(nonce[:], nonceSlice)

		if store != nil {
			store.Set(nonce, storage.RequestInfo{
				Key:       pubKey,
				Email:     identity.UserId.Email,
				Timestamp: time.Now(),
			})
		}

		m := mail.OutgoingMail{
			Message:        hex.EncodeToString(nonce[:]),
			RecipientEmail: identity.UserId.Email,
			RecipientKey:   pubKey,
			Attachment:     []byte{},
			GPG:            gpgUtil,
		}
		b, err := m.Bytes()
		if err != nil {
			log.Printf("Error constructing return email: %v\n", err)
			return
		}
		log.Println(string(b))
		file, err := os.Create("nonce.eml")
		if err != nil {
			log.Printf("Error creating return email: %v\n", err)
			return
		}
		defer func(f *os.File) { _ = f.Close() }(file) // When using `defer` inside a loop, don't access closure.
		_, err = file.Write(b)
		if err != nil {
			log.Printf("Error writing return email: %v\n", err)
			return
		}
	}
}
