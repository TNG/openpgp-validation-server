package smtp

import (
	"github.com/mhale/smtpd"
	"log"
	"net"
)

// Handler is a callback type for treating received mail
type Handler func(mail *MailEnvelope)

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
	log.Printf("Incoming mail Origin: %v From: %v To: %v\n", origin, fromAddress, toAddresses)
	mail := MailEnvelope{fromAddress, toAddresses, data}
	server.Handler(&mail)
}

// Run starts a goroutine which listens and processes mail as it arrives.
func (server *MailServer) Run() {
	go log.Panic(smtpd.ListenAndServe(server.Address, server.mailHandler, "openpgp-validation-server", ""))
}
