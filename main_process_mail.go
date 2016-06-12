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

func serveSMTPRequestReceiver(host string) {
	smtpServer := smtp.NewServer(host, getIncomingMailEnvelopeHandler())
	smtpServer.Run()
}

func getIncomingMailEnvelopeHandler() func(*smtp.MailEnvelope) {
	return func(incomingMail *smtp.MailEnvelope) {
		handleIncomingMailEnvelope(incomingMail)
	}
}

func getIncomingMailHandler() func(io.Reader) {
	return func(incomingMail io.Reader) {
		handleIncomingMail(incomingMail)
	}
}

func handleIncomingMailEnvelope(incomingMail *smtp.MailEnvelope) {
	handleIncomingMail(bytes.NewReader(incomingMail.Content))
}

func handleIncomingMail(incomingMail io.Reader) {
	if gpgUtil == nil {
		log.Panicf("Missing gpg init!")
	}

	for _, responseMail := range validator.HandleMail(incomingMail, gpgUtil, store) {
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
			From:    mail.From(),
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
