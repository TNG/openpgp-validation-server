package emailserver

import (
	"log"
	"net"
	"mime"
	"bytes"
	"io"
	"io/ioutil"
	"net/mail"
	"mime/multipart"
	"github.com/mhale/smtpd"
	"errors"
	"fmt"
)

type Mail struct {
	FromAddress string
	ToAddresses []string
	Subject string
	Text string
	Attachments [][]byte
}

type Handler func(mail *Mail)
type Parser func(message *mail.Message) (*Mail, error)

// MailServer contains the information necessary to run
// a server which receives and handles mail.
type MailServer struct {
	Address string
	Handler Handler
	Parser Parser
}

// Create returns a MailServer struct given a listening address and a mail handler.
func Create(Address string, Handler Handler) *MailServer {
	return &MailServer{Address, Handler, parseMail}
}

func (server *MailServer) mailHandler(origin net.Addr, fromAddress string, toAddresses []string, data []byte) {
	message, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		log.Print(err)
		return
	}
	mail, err := server.Parser(message)
	if err != nil {
		log.Print(err)
		return
	}
	mail.FromAddress = fromAddress
	mail.ToAddresses = toAddresses
	server.Handler(mail)
}

func parseMail(message *mail.Message) (*Mail, error) {
	subject := message.Header.Get("Subject")
	contentType := message.Header.Get("Content-Type")
	contentType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, err
	}
	if contentType == "multipart/mixed" {
		mail, err := parseMultipartMixedMessage(message.Body, params)
		if err != nil {
			return nil, err
		}
		mail.Subject = subject
		return mail, nil
	}
	return nil, fmt.Errorf("Unknown mail content type: %s", contentType)
}

func parseMultipartMixedMessage(messageBody io.Reader, params map[string]string) (*Mail, error) {
	boundary, ok := params["boundary"]
	if !ok {
		return nil, errors.New("multipart/mixed mail without boundary")
	}

	reader := multipart.NewReader(messageBody, boundary)
	mail := &Mail{}
	for {
		part, err := reader.NextPart()
		if err != nil {
			if err == io.EOF {
				return mail, nil
			}
			return nil, err
		}
		contentType := part.Header.Get("Content-Type")
		switch contentType {
		case "text/plain":
			text, err := ioutil.ReadAll(part)
			if err != nil {
				return nil, err
			}
			mail.Text += string(text)
		case "":
			return nil, errors.New("No Content-Type found in multipart message part")
		default:
			return nil, errors.New("Unknown Content-Type (%s) found in multipart message part")
		}
	};
}

// Run starts a goroutine which listens and processes mail as it arrives.
func (server *MailServer) Run() {
	go log.Fatal(smtpd.ListenAndServe(server.Address, server.mailHandler, "gpg-validation-server", ""))
}
