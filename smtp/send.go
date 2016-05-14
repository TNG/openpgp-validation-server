package smtp

import (
	"net/smtp"
)

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
