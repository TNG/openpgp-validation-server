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
		message, _ := mail.ReadMessage(bytes.NewReader(data))
		log.Printf("Received mail from %s for %s: %s", from, to[0], message) // TODO Why is message nil?
		resultChannel <- to[0]
	}

	go func() {
		err := smtpd.ListenAndServe("127.0.0.1:2525", mailHandler, "TestSendMailServer", "")
		if err != nil {
			log.Fatal(err)
		}
	}()

	time.Sleep(2 * time.Second) // TODO Better synchronisation
	SendMail("test@server.local", "Test Server", "Here is your mail!")

	result := <-resultChannel
	if result != "Test Server" {
		log.Fatal(result)
	}
}
