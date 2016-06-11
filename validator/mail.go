package validator

import (
	"encoding/hex"
	"io"
	"log"
	"time"

	"github.com/TNG/gpg-validation-server/gpg"
	"github.com/TNG/gpg-validation-server/mail"
	"github.com/TNG/gpg-validation-server/storage"
)

// MailInfo contains the result of processing a given mail.
type MailInfo struct {
	entity *mail.MimeEntity
}

// HandleMail return zero or more outgoing mails in response to an incoming mail.
func HandleMail(incomingMail io.Reader, gpgUtil mail.GpgUtility, store storage.GetSetDeleter) (responses []mail.OutgoingMail) {
	responses = []mail.OutgoingMail{}

	parser := mail.Parser{Gpg: gpgUtil}
	requestEntity, err := parser.ParseMail(incomingMail)
	if err != nil {
		log.Printf("Cannot parse mail: %s", err)
		return
	}

	request := &MailInfo{entity: requestEntity}

	if !request.isSigned() {
		log.Printf("Mail from %s is missing valid signature. Doing nothing.", request.getSender())
		return
	}

	log.Printf("Mail from %s has valid signature.", request.getSender())

	requestKey := request.getPublicKey()

	for _, identity := range requestKey.Identities {
		nonce, err := generateNonce()
		if err != nil {
			log.Fatalf("Could not generate nonce, stopping now: %v\n", err)
			return
		}
		nonceString := hex.EncodeToString(nonce[:])

		log.Printf("Sending mail to %s with nonce %s\n", identity.UserId.Email, nonceString)

		if store != nil {
			store.Set(nonce, storage.RequestInfo{
				Key:       requestKey,
				Email:     identity.UserId.Email,
				Timestamp: time.Now(),
			})
		}

		responses = append(responses, mail.OutgoingMail{
			Message:        nonceString,
			RecipientEmail: identity.UserId.Email,
			RecipientKey:   requestKey,
			Attachment:     nil,
			GPG:            gpgUtil,
		})
	}
	return
}

// IsSigned returns true if the corresponding mail has a valid signature.
func (info *MailInfo) isSigned() bool {
	return info.entity.SignedBy != nil
}

// GetPublicKey returns the public key that was used to signed the corresponding mail.
// Returns nil if signature is missing or invalid.
func (info *MailInfo) getPublicKey() gpg.Key {
	return info.entity.SignedBy
}

// GetSender returns the sender as given in the mail header.
func (info *MailInfo) getSender() string {
	return info.entity.GetSender()
}
