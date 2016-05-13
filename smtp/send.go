package smtp

import (
	"fmt"
	"net/smtp"
)

// MailEnvelope describes an Email "Envelope", the minimal information
// necessary to successfully send an Email via SMTP
type MailEnvelope struct {
	Sender, Recipient, Message string
}

// SendMailer interface is for classes that can send mail.
type SendMailer interface {
	SendMail(MailEnvelope) error
}

// Send the envelope via the specified SendMailer
func (envelope MailEnvelope) Send(mailer SendMailer) (err error) {
	return mailer.SendMail(envelope)
}

// SingleServerSendMailer sends mails via one specified SMTP server
type SingleServerSendMailer struct {
	Server string
}

// SendMail tries to send the given mail envelope via SMTP localhost
func (mailer SingleServerSendMailer) SendMail(envelope MailEnvelope) (err error) {
	// Connect to the remote SMTP server.
	c, err := smtp.Dial(mailer.Server)
	if err != nil {
		return err
	}
	// In all cases, close the connection and quit.
	defer func() {
		cerr := c.Quit()
		if err == nil {
			err = cerr
		}
	}()

	if err = c.Mail(envelope.Sender); err != nil {
		return err
	}
	if err = c.Rcpt(envelope.Recipient); err != nil {
		return err
	}

	// Send the email body.
	wc, err := c.Data()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(wc, envelope.Message)
	if err != nil {
		return err
	}
	return wc.Close()
}
