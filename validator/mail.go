package validator

import (
	"fmt"
	"github.com/TNG/gpg-validation-server/gpg"
	"github.com/TNG/gpg-validation-server/mail"
	"io"
)

// MailInfo contains the result of processing a given mail.
type MailInfo struct {
	entity *mail.MimeEntity
}

// HandleMail returns information about a received mail.
// Returns an error if there is a problem.
// TODO #9 Later it will contain the response mail.
func HandleMail(inputMail io.Reader, gpgUtil mail.GpgUtility) (*MailInfo, error) {

	parser := mail.Parser{Gpg: gpgUtil}
	entity, err := parser.ParseMail(inputMail)

	if err != nil {
		return nil, fmt.Errorf("Cannot parse mail: %s", err)
	}

	return &MailInfo{entity: entity}, nil
}

// IsSigned returns true if the corresponding mail has a valid signature.
func (info *MailInfo) IsSigned() bool {
	return info.entity.SignedBy != nil
}

// GetPublicKey returns the public key that was used to signed the corresponding mail.
// Returns nil if signature is missing or invalid.
func (info *MailInfo) GetPublicKey() gpg.Key {
	return info.entity.SignedBy
}
