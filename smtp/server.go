package smtp

import (
	"github.com/mhale/smtpd"
	"log"
	"net"
)

// Mail describes a message received by the mail server
type Mail struct {
	FromAddress string
	ToAddresses []string
	Content     []byte
}

// Handler is a callback type for treating received mail
type Handler func(mail *Mail)

// MailServer contains the information necessary to run
// a server which receives and handles mail.
type MailServer struct {
	Address string
	Handler Handler
}

// NewServer returns a MailServer struct given a listening address and a mail handler.
func NewServer(Address string, Handler Handler) *MailServer {
	return &MailServer{Address, Handler}
}

func (server *MailServer) mailHandler(origin net.Addr, fromAddress string, toAddresses []string, data []byte) {
	mail := Mail{fromAddress, toAddresses, data}
	server.Handler(&mail)
}

// Run starts a goroutine which listens and processes mail as it arrives.
func (server *MailServer) Run() {
	go log.Fatal(smtpd.ListenAndServe(server.Address, server.mailHandler, "gpg-validation-server", ""))
}
