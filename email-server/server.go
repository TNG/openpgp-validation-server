package emailserver

import (
	"bytes"
	"github.com/mhale/smtpd"
	"io"
	"log"
	"net"
)

type Mail struct {
	FromAddress string
	ToAddresses []string
	Subject     string
	Text        string
	Attachments [][]byte
}

type Handler func(mail *Mail)
type Parser func(reader io.Reader) (*MimeEntity, error)

// MailServer contains the information necessary to run
// a server which receives and handles mail.
type MailServer struct {
	Address string
	Handler Handler
	Parser  Parser
}

// Create returns a MailServer struct given a listening address and a mail handler.
func Create(Address string, Handler Handler) *MailServer {
	return &MailServer{Address, Handler, parseMail}
}

func (server *MailServer) mailHandler(origin net.Addr, fromAddress string, toAddresses []string, data []byte) {
	reader := bytes.NewReader(data)
	parsedMail, err := server.Parser(reader)
	if err != nil {
		log.Print("Error when parsing mail: ", err)
	}
	mail := &Mail{
		fromAddress,
		toAddresses,
		parsedMail.getHeader("Subject", ""),
		findFirstText(parsedMail),
		findAttachements(parsedMail),
	}
	mail.FromAddress = fromAddress
	mail.ToAddresses = toAddresses
	server.Handler(mail)
}

func findFirstText(entity *MimeEntity) string {
	if len(entity.Text) > 0 {
		return entity.Text
	}
	for _, part := range entity.Parts {
		text := findFirstText(&part)
		if len(text) > 0 {
			return text
		}
	}
	return ""
}

func findAttachements(entity *MimeEntity) [][]byte {
	return nil
}

// Run starts a goroutine which listens and processes mail as it arrives.
func (server *MailServer) Run() {
	go log.Fatal(smtpd.ListenAndServe(server.Address, server.mailHandler, "gpg-validation-server", ""))
}
