package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/TNG/openpgp-validation-server/mail"
	"github.com/TNG/openpgp-validation-server/smtp"
	"github.com/TNG/openpgp-validation-server/validator"
)

func serveSMTPRequestReceiver(host, httpHost string) {
	smtpServer := smtp.NewServer(host, getIncomingMailEnvelopeHandler(httpHost))
	smtpServer.Run()
}

func getIncomingMailEnvelopeHandler(httpHost string) func(*smtp.MailEnvelope) {
	return func(incomingMail *smtp.MailEnvelope) {
		handleIncomingMailEnvelope(incomingMail, httpHost)
	}
}

func getIncomingMailHandler(httpHost string) func(io.Reader) {
	return func(incomingMail io.Reader) {
		handleIncomingMail(incomingMail, httpHost)
	}
}

func handleIncomingMailEnvelope(incomingMail *smtp.MailEnvelope, httpHost string) {
	handleIncomingMail(bytes.NewReader(incomingMail.Content), httpHost)
}

func handleIncomingMail(incomingMail io.Reader, httpHost string) {
	if gpgUtil == nil {
		log.Panicf("Missing gpg init!")
	}

	for _, responseMail := range validator.HandleMail(incomingMail, gpgUtil, store, httpHost) {
		sendOutgoingMail("nonce", &responseMail)
	}
}

// sendOutgoingMail sends a mail via SMTP if configured. A corresponding mail file is written for debugging purposes.
// Returns `true` if mail could be successfully submitted, `false` otherwise.
// There is no guarantee, that the mail actually arrives in the recipients mailbox.
func sendOutgoingMail(mailType string, mail *mail.OutgoingMail) (success bool) {
	success = false

	content, err := mail.Bytes()
	if err != nil {
		log.Printf("Cannot construct %s email: %v\n", mailType, err)
		return
	}
	file, err := os.Create(fmt.Sprintf("%s_%d_%s.eml", mailType, time.Now().Unix(), mail.RecipientEmail))
	if err != nil {
		log.Printf("Cannot create %s email: %v\n", mailType, err)
		return
	}
	defer func() { _ = file.Close() }()
	_, err = file.Write(content)
	if err != nil {
		log.Printf("Cannot write %s email: %v\n", mailType, err)
		return
	}

	if mailSender != nil {
		err = mailSender.SendMail(&smtp.MailEnvelope{
			From:    smtpMailFrom,
			To:      []string{mail.RecipientEmail},
			Content: content,
		})
		if err != nil {
			log.Printf("Cannot send %s mail to %s: %v\n", mailType, mail.RecipientEmail, err)
			return
		}
	}

	return true
}
