package smtp

import (
	"net/smtp"
)

// MailSender allows simple mail sending.
type MailSender interface {
	SendMail(envelope *MailEnvelope) error
}

// SingleServerSendMailer sends mails via one specified SMTP server.
type SingleServerSendMailer struct {
	Server string
}

// NewSingleServerSendMailer returns a MailSender offering outgoing SMTP functionality.
func NewSingleServerSendMailer(Server string) *SingleServerSendMailer {
	return &SingleServerSendMailer{Server}
}

// SendMail tries to send the given mail envelope via SMTP localhost
func (mailer SingleServerSendMailer) SendMail(envelope *MailEnvelope) (err error) {
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

	if err = c.Mail(envelope.From); err != nil {
		return err
	}
	for _, to := range envelope.To {
		if err = c.Rcpt(to); err != nil {
			return err
		}
	}

	// Send the email body.
	body, err := c.Data()
	if err != nil {
		return err
	}
	_, err = body.Write(envelope.Content)
	if err != nil {
		return err
	}
	return body.Close()
}
