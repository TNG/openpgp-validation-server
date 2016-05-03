package emailserver

import (
	"testing"
	"fmt"
	"time"
	"net/mail"
	"gpg-validation-server/email-client"
	"strings"
)

var receiveChan = make(chan string)

func init() {
	server := Create("127.0.0.1:2525", mailTestHandler)
	fakeParser := func (message *mail.Message) (*Mail, error) {
		return &Mail{"", nil, "QWERTYIOP", "", nil}, nil
	}
	server.Parser = fakeParser
	go server.Run()
	time.Sleep(1 * time.Millisecond)
}

func mailTestHandler(mail *Mail) {
	receiveChan <- mail.FromAddress
	receiveChan <- mail.ToAddresses[0]
	receiveChan <- mail.Subject
}

func TestReceiveMail(t *testing.T) {
	expectedFromAddress := "ray@tomlinson.net"
	expectedToAddress := "ray.tomlinson@mail.org"
	expectedSubject := "QWERTYIOP"
	_ = emailclient.SendMail(expectedFromAddress, expectedToAddress, "\n\n")
	receivedFromAddress := <-receiveChan
	receivedToAddress := <-receiveChan
	receivedSubject := <-receiveChan

	if receivedFromAddress != expectedFromAddress {
		t.Error("Expected:", expectedFromAddress, " Received:", receivedFromAddress)
	}

	if receivedToAddress != expectedToAddress {
		t.Error("Expected:", expectedToAddress, " Received:", receivedToAddress)
	}

	if receivedSubject != expectedSubject {
		t.Error("Expected:", expectedSubject, " Received:", receivedSubject)
	}
}

func parseMailFromString(source string) (*Mail, error) {
	reader := strings.NewReader(source)
	message, err := mail.ReadMessage(reader)
	if err != nil {
		return nil, err
	}
	return parseMail(message)
}

func createMailString(subject, contentType, text string) string {
	lines := []string{
		fmt.Sprintf("Subject: %s", subject),
		fmt.Sprintf("Content-Type: %s", contentType),
		"",
		"--f",
		"Content-Type: text/plain",
		"",
		text,
		"--f--",
		""}
	return strings.Join(lines, "\r\n")
}

func TestParseMailSubject(t *testing.T) {
	mail, err := parseMailFromString(createMailString("Test", "multipart/mixed; boundary=\"f\"", "text"))
	if err != nil {
		t.Error("Error while parsing mail subject:", err)
	}
	if mail.Subject != "Test" {
		t.Error("Expected subject 'Test', got", mail.Subject)
	}
}

func TestParseMailInvalidContentType(t *testing.T) {
	mail, err := parseMailFromString(createMailString("S", "blah", ""))
	if err == nil {
		t.Error("Expected an error when parsing mail with invalid content type")
	}
	if mail != nil {
		t.Error("Must not parse mail with invalid content type")
	}
}

func TestParseMailWithoutBoundaryString(t *testing.T) {
	mail, err := parseMailFromString(createMailString("S", "multipart/mixed;", ""))
	if err == nil {
		t.Error("Expected an error when parsing mail without boundary string")
	}
	if mail != nil {
		t.Error("Must not parse mail without boundary string")
	}
}

func TestParseMailMessage(t *testing.T) {
	mail, err := parseMailFromString(createMailString(
		"S", "multipart/mixed; boundary=\"f\"", "Hello there!"))

	if err != nil {
		t.Error("Error while parsing a multipart mail:", err)
	}
	if mail.Text != "Hello there!" {
		t.Errorf("Expected message text 'Hello there!', got '%s'", mail.Text)
	}
}
