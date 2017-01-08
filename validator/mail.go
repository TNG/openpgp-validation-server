package validator

import (
	"bytes"
	"encoding/hex"
	"io"
	"log"
	"text/template"
	"time"

	"github.com/TNG/openpgp-validation-server/gpg"
	"github.com/TNG/openpgp-validation-server/mail"
	"github.com/TNG/openpgp-validation-server/storage"
)

var requestResponseMessage = template.Must(template.ParseFiles("./templates/nonceMail.tmpl"))

// MailInfo contains the result of processing a given mail.
type MailInfo struct {
	entity *mail.MimeEntity
}

// HandleMail returns zero or more outgoing mails in response to an incoming mail.
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
		log.Printf("Mail from '%s' is missing valid signature.", request.getSender())
		return
	}

	log.Printf("Mail from '%s' has valid signature.", request.getSender())

	requestKey := request.getPublicKey()

	for _, identity := range requestKey.Identities {
		nonce, err := generateNonce()
		if err != nil {
			log.Panicf("Cannot generate nonce: %v\n", err)
			return
		}
		nonceString := hex.EncodeToString(nonce[:])
		message := request.getNonceMessage(nonceString, requestKey.PrimaryKey.KeyIdString())

		log.Printf("Sending nonce mail to %s with nonce %s\n", identity.UserId.Email, nonceString)

		if store != nil {
			store.Set(nonce, storage.RequestInfo{
				Key:       requestKey,
				Email:     identity.UserId.Email,
				Timestamp: time.Now(),
			})
		}

		responses = append(responses, mail.OutgoingMail{
			Message:        message,
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

func (info *MailInfo) getNonceMessage(nonceString, fingerprint string) string {
	message := new(bytes.Buffer)
	err := requestResponseMessage.Execute(message, struct{ Nonce, Requester, Fingerprint string }{
		Nonce:       nonceString,
		Requester:   info.getSender(),
		Fingerprint: fingerprint,
	})
	if err != nil {
		log.Panicf("Cannot generate nonce message: %v\n", err)
		return ""
	}

	return message.String()
}
