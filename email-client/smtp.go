package emailclient

import (
	"fmt"
	"net/smtp"
)

// SendMail tries to send the given message from the sender to the recipient
func SendMail(sender, recipient, message string) (err error) {
	// Connect to the remote SMTP server.
	c, err := smtp.Dial("127.0.0.1:2525")
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

	if err = c.Mail(sender); err != nil {
		return err
	}
	if err = c.Rcpt(recipient); err != nil {
		return err
	}

	// Send the email body.
	wc, err := c.Data()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(wc, message)
	if err != nil {
		return err
	}
	return wc.Close()
}
