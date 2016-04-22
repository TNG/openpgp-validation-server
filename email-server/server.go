package emailserver

import (
    "github.com/mhale/smtpd"
)


type MailServer struct {
    Address string
    Handler smtpd.Handler
}

func Create(Address string, Handler smtpd.Handler) (*MailServer) {
    return &MailServer{Address, Handler}
}

func (server *MailServer) Run() {
    go smtpd.ListenAndServe(server.Address, server.Handler, "gpg-validation-server", "")
}
