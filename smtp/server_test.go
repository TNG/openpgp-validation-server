package smtp

import (
	"log"
	"strings"
	"testing"
	"time"
)

var receiveChan = make(chan string)

func init() {
	server := NewServer("127.0.0.1:2525", mailTestHandler)
	go server.Run()
	time.Sleep(1 * time.Millisecond)
}

func mailTestHandler(mail *MailEnvelope) {
	receiveChan <- mail.From
	receiveChan <- mail.To[0]
	receiveChan <- string(mail.Content)
}

func TestReceiveMail(t *testing.T) {
	expectedFrom := "ray@tomlinson.net"
	expectedToAddress := "ray.tomlinson@mail.org"
	message := []byte("QWERTYIOP")
	mailer := SingleServerSendMailer{Server: "127.0.0.1:2525"}
	mail := MailEnvelope{expectedFrom, []string{expectedToAddress}, message}
	err := mailer.SendMail(mail)
	if err != nil {
		log.Fatal(err)
	}
	receivedFrom := <-receiveChan
	receivedToAddress := <-receiveChan
	receivedContent := <-receiveChan

	if receivedFrom != expectedFrom {
		t.Fatal("Expected:", expectedFrom, " Received:", receivedFrom)
	}

	if receivedToAddress != expectedToAddress {
		t.Fatal("Expected:", expectedToAddress, " Received:", receivedToAddress)
	}

	lines := strings.Split(receivedContent, "\n")
	if len(lines) != 5 {
		t.Fatal("Expected four lines, got: ", lines)
	}
	if lines[3] != string(message)+"\r" {
		t.Fatal("Expected:", message, " Received:", lines[3])
	}
}
