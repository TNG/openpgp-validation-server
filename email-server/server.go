package emailserver

import (
	"log"

	"github.com/mhale/smtpd"
)

// MailServer contains the information necessary to run
// a server which receives and handles mail.
type MailServer struct {
	Address string
	Handler smtpd.Handler
}

// Create returns a MailServer struct given a listening address and a mail handler.
func Create(Address string, Handler smtpd.Handler) *MailServer {
	return &MailServer{Address, Handler}
}

// Run starts a goroutine which listens and processes mail as it arrives.
func (server *MailServer) Run() {
	go log.Fatal(smtpd.ListenAndServe(server.Address, server.Handler, "gpg-validation-server", ""))
}
