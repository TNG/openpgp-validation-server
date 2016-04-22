package emailclient

import (
	"bytes"
	"github.com/mhale/smtpd"
	"log"
	"net"
	"net/mail"
	"testing"
	"time"
)

func TestSendEmail(t *testing.T) {
	resultChannel := make(chan string)

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
		err := smtpd.ListenAndServe("127.0.0.1:2525", mailHandler, "TestSendMailServer", "")
		if err != nil {
			log.Fatal(err)
		}
	}()

	time.Sleep(2 * time.Second) // TODO Better synchronisation
	SendMail("test@server.local", "Test Server", "Subject: Here is your mail!\n\nContent of mail.")

	result := <-resultChannel
	if result != "Test Server" {
		log.Fatal(result)
	}
}
