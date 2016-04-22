package emailserver

import (
	"bytes"
	"net"
	"net/mail"
	"testing"
	"gpg-validation-server/email-client"
	"gpg-validation-server/email-server"
	"time"
	"fmt"
)

var received string

func init() {
	server := emailserver.Create("127.0.0.1:2525", mailHandler)
	go server.Run()
	time.Sleep(1 * time.Millisecond)
}

func mailHandler(origin net.Addr, from string, to []string, data []byte) {
	mail.ReadMessage(bytes.NewReader(data))
	received = fmt.Sprintf("%s -> %s", from, to[0])
}

func TestReceiveMail(t *testing.T) {
	received = ""
	expected := "ray@tomlinson.net -> ray.tomlinson@mail.org"
	emailclient.SendMail("ray@tomlinson.net", "ray.tomlinson@mail.org", "QWERTYIOP")
	if received != expected {
		t.Error("Expected:", expected, " Received:", received)
	}
}

