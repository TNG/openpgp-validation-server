package emailserver

import (
	"github.com/TNG/gpg-validation-server/email-client"
	"io"
	"net/textproto"
	"testing"
	"time"
)

var receiveChan = make(chan string)

func init() {
	server := Create("127.0.0.1:2525", mailTestHandler)
	fakeParser := func(reader io.Reader) (*MimeEntity, error) {
		header := textproto.MIMEHeader{}
		header.Set("Subject", "QWERTYIOP")
		var parts []MimeEntity
		return &MimeEntity{header, "Hello World!", parts, nil}, nil
	}
	server.parser = fakeParser
	go server.Run()
	time.Sleep(1 * time.Millisecond)
}

func mailTestHandler(mail *Mail) {
	receiveChan <- mail.FromAddress
	receiveChan <- mail.ToAddresses[0]
	receiveChan <- mail.Subject
	receiveChan <- mail.Text
}

func TestReceiveMail(t *testing.T) {
	expectedFromAddress := "ray@tomlinson.net"
	expectedToAddress := "ray.tomlinson@mail.org"
	expectedSubject := "QWERTYIOP"
	expectedText := "Hello World!"
	_ = emailclient.SendMail(expectedFromAddress, expectedToAddress, "\n\n")
	receivedFromAddress := <-receiveChan
	receivedToAddress := <-receiveChan
	receivedSubject := <-receiveChan
	receivedText := <-receiveChan

	if receivedFromAddress != expectedFromAddress {
		t.Error("Expected:", expectedFromAddress, " Received:", receivedFromAddress)
	}

	if receivedToAddress != expectedToAddress {
		t.Error("Expected:", expectedToAddress, " Received:", receivedToAddress)
	}

	if receivedSubject != expectedSubject {
		t.Error("Expected:", expectedSubject, " Received:", receivedSubject)
	}

	if receivedText != expectedText {
		t.Error("Expected:", expectedText, " Received:", receivedText)
	}
}
