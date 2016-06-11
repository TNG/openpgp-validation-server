package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/TNG/gpg-validation-server/mail"
	"github.com/TNG/gpg-validation-server/smtp"
	"github.com/TNG/gpg-validation-server/validator"
)

func serveSMTPRequestReceiver(host string, gpgUtil mail.GpgUtility) {
	smtpServer := smtp.NewServer(host, getIncomingMailEnvelopeHandler(gpgUtil))
	smtpServer.Run()
}

func getIncomingMailEnvelopeHandler(gpgUtil mail.GpgUtility) func(*smtp.MailEnvelope) {
	return func(incomingMail *smtp.MailEnvelope) {
		handleIncomingMailEnvelope(incomingMail, gpgUtil)
	}
}

func getIncomingMailHandler(gpgUtil mail.GpgUtility) func(io.Reader) {
	return func(incomingMail io.Reader) {
		handleIncomingMail(incomingMail, gpgUtil)
	}
}

func handleIncomingMailEnvelope(incomingMail *smtp.MailEnvelope, gpgUtil mail.GpgUtility) {
	handleIncomingMail(bytes.NewReader(incomingMail.Content), gpgUtil)
}

func handleIncomingMail(incomingMail io.Reader, gpgUtil mail.GpgUtility) {
	for _, responseMail := range validator.HandleMail(incomingMail, gpgUtil, store) {
		responseBytes, err := responseMail.Bytes()
		if err != nil {
			log.Printf("Error constructing return email: %v\n", err)
			return
		}
		file, err := os.Create(fmt.Sprintf("nonce_%d_%s.eml", time.Now().Unix(), responseMail.RecipientEmail))
		if err != nil {
			log.Printf("Error creating return email: %v\n", err)
			return
		}
		defer func(f *os.File) { _ = f.Close() }(file) // Don't access closure in func-body, when using 'defer' in loop.
		_, err = file.Write(responseBytes)
		if err != nil {
			log.Printf("Error writing return email: %v\n", err)
			return
		}
	}
}
