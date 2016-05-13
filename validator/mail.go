package validator

import "errors"

type mailInfo interface {
	IsSigned() bool
	GetPublicKey() []byte
}

// HandleMail requires information on the received mail, and returns an error
// if there is a problem with it. Later it will return the response mail.
func HandleMail(info mailInfo) error {
	if !info.IsSigned() {
		return errors.New("Mail not signed")
	}
	return nil
}
