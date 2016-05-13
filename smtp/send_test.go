package smtp

import (
	"bytes"
	"github.com/mhale/smtpd"
	"log"
	"net"
	"net/mail"
	"testing"
	"time"
)

type mockSendMailer struct {
	expectedSender, expectedRecipient, expectedMessage string
}

// SendMail that just checks expected Values
func (mailer mockSendMailer) SendMail(envelope MailEnvelope) (err error) {
	if envelope.Sender != mailer.expectedSender {
		log.Fatal(envelope.Sender)
	}
	if envelope.Recipient != mailer.expectedRecipient {
		log.Fatal(envelope.Recipient)
	}
	if envelope.Message != mailer.expectedMessage {
		log.Fatal(envelope.Message)
	}
	return nil
}

func TestEmail(t *testing.T) {
	mailer := mockSendMailer{"sender@localhost.local", "recipient@localhost.local", "Hey, you!"}
	mail := MailEnvelope{"sender@localhost.local", "recipient@localhost.local", "Hey, you!"}
	_ = mailer.SendMail(mail)
}

func runMailServer(resultChannel chan string) {
	mailHandler := func(origin net.Addr, from string, to []string, data []byte) {
		message, err := mail.ReadMessage(bytes.NewReader(data))
		if err != nil {
			log.Fatalf("ERROR: Received mail from %s for %s: %v", from, to[0], err)
		} else {
			log.Printf("Received mail from %s for %s: %v", from, to[0], message)
		}
		resultChannel <- to[0]
	}

	go func() {
		err := smtpd.ListenAndServe("127.0.0.1:2526", mailHandler, "TestSendMailServer", "")
		if err != nil {
			log.Fatal(err)
		}
	}()
}

func TestSingleServerSendMailer(t *testing.T) {
	resultChannel := make(chan string)
	mailer := SingleServerSendMailer{"127.0.0.1:2526"}
	mail := MailEnvelope{"test@server.local", "Test Server", "Subject: Here is your mail!\n\nContent of mail."}
	runMailServer(resultChannel)

	time.Sleep(2 * time.Second) // TODO Better synchronisation
	err := mailer.SendMail(mail)
	if err != nil {
		log.Fatal(err)
	}

	result := <-resultChannel
	if result != "Test Server" {
		log.Fatal(result)
	}
}
