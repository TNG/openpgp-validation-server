package emailclient

import (
	"fmt"
	"log"
	"net/smtp"
)

func SendMail(email, recipient, message string) {
	// Connect to the remote SMTP server.
	c, err := smtp.Dial("127.0.0.1:2525")
	if err != nil {
		log.Fatal(err)
	}

	// Set the sender and recipient first
	if err := c.Mail(email); err != nil {
		log.Fatal(err)
	}
	if err := c.Rcpt(recipient); err != nil {
		log.Fatal(err)
	}

	// Send the email body.
	wc, err := c.Data()
	if err != nil {
		log.Fatal(err)
	}
	_, err = fmt.Fprintf(wc, message)
	if err != nil {
		log.Fatal(err)
	}
	err = wc.Close()
	if err != nil {
		log.Fatal(err)
	}

	// Send the QUIT command and close the connection.
	err = c.Quit()
	if err != nil {
		log.Fatal(err)
	}
}
