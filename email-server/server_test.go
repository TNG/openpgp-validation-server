package emailserver

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"net/mail"
	"testing"
	"time"

	"github.com/TNG/gpg-validation-server/email-client"
)

var receive_chan = make(chan string)

func init() {
	server := Create("127.0.0.1:2525", mailHandler)
	go server.Run()
	time.Sleep(1 * time.Millisecond)
}

func mailHandler(origin net.Addr, from string, to []string, data []byte) {
	_, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		log.Fatal(err)
	}
	receive_chan <- fmt.Sprintf("%s -> %s", from, to[0])
}

func TestReceiveMail(t *testing.T) {
	expected := "ray@tomlinson.net -> ray.tomlinson@mail.org"
	emailclient.SendMail("ray@tomlinson.net", "ray.tomlinson@mail.org", "Subject: QWERTYIOP\n\nBody")
	received := <-receive_chan
	if received != expected {
		t.Error("Expected:", expected, " Received:", received)
	}
}
