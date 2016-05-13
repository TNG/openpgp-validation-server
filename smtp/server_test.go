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

func mailTestHandler(mail *Mail) {
	receiveChan <- mail.FromAddress
	receiveChan <- mail.ToAddresses[0]
	receiveChan <- string(mail.Content)
}

func TestReceiveMail(t *testing.T) {
	expectedFromAddress := "ray@tomlinson.net"
	expectedToAddress := "ray.tomlinson@mail.org"
	message := "QWERTYIOP"
	mailer := SingleServerSendMailer{Server: "127.0.0.1:2525"}
	mail := MailEnvelope{expectedFromAddress, expectedToAddress, message}
	err := mailer.SendMail(mail)
	if err != nil {
		log.Fatal(err)
	}
	receivedFromAddress := <-receiveChan
	receivedToAddress := <-receiveChan
	receivedContent := <-receiveChan

	if receivedFromAddress != expectedFromAddress {
		t.Fatal("Expected:", expectedFromAddress, " Received:", receivedFromAddress)
	}

	if receivedToAddress != expectedToAddress {
		t.Fatal("Expected:", expectedToAddress, " Received:", receivedToAddress)
	}

	lines := strings.Split(receivedContent, "\n")
	if len(lines) != 5 {
		t.Fatal("Expected four lines, got: ", lines)
	}
	if lines[3] != message+"\r" {
		t.Fatal("Expected:", message, " Received:", lines[3])
	}
}
