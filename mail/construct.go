package mail

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/TNG/openpgp-validation-server/gpg"
)

// MessageEncrypter is a struct able to sign a message and encrypt it for the recipient key
type MessageEncrypter interface {
	EncryptMessage(output io.Writer, recipientKey gpg.Key) (plaintext io.WriteCloser, err error)
	ServerIdentity() string
}

// OutgoingMail describes the contents of the mail to be sent
type OutgoingMail struct {
	Message        string
	RecipientEmail string
	RecipientKey   gpg.Key
	Attachment     []byte
	GPG            MessageEncrypter
}

// From returns the sender of the mail.
func (m OutgoingMail) From() string {
	return m.GPG.ServerIdentity()
}

// Bytes returns the given message as an OpenPGP/MIME encrypted and signed message (RFC 2440 and 3156)
func (m OutgoingMail) Bytes() ([]byte, error) {
	w := bytes.Buffer{}
	now := time.Now()
	identityParts := strings.Split(m.GPG.ServerIdentity(), "><@")
	serverDomain := identityParts[len(identityParts)-1]
	empw := NewEncodingMultipartWriter(&w, "encrypted", "application/pgp-encrypted", map[string]string{
		"Date":                now.Format(time.RFC1123Z),
		"From":                m.From(),
		"To":                  m.RecipientEmail,
		"Message-ID":          "<" + now.Format(time.RFC3339Nano) + "@" + serverDomain + ">",
		"Subject":             "OpenPGP Key Validation",
		"X-Mailer":            "github.com/TNG/openpgp-validation-server",
		"Content-Description": "OpenPGP encrypted message",
	})

	if err := empw.WritePGPMIMEVersion(); err != nil {
		return nil, err
	}

	partWriter, err := empw.WriteInlineFile("encrypted.asc", "application/octet-stream", "OpenPGP encrypted message")
	if err != nil {
		return nil, err
	}

	plaintext, err := m.GPG.EncryptMessage(partWriter, m.RecipientKey)
	if err != nil {
		return nil, err
	}

	encryptedMultipartWriter := NewEncodingMultipartWriter(plaintext, "mixed", "", nil)

	if err = encryptedMultipartWriter.WritePlainText(m.Message); err != nil {
		return nil, err
	}

	if err = m.handleAttachment(encryptedMultipartWriter); err != nil {
		return nil, err
	}

	// Close all writers in the correct order:
	if err = encryptedMultipartWriter.Close(); err != nil {
		return nil, err
	}
	if err = plaintext.Close(); err != nil {
		return nil, err
	}
	if err = empw.Close(); err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

func (m OutgoingMail) handleAttachment(w *EncodingMultipartWriter) error {
	if m.Attachment == nil {
		return nil
	}
	fileName := "0x" + m.RecipientKey.PrimaryKey.KeyIdString() + ".asc"
	attachmentWriter, err := w.WriteAttachedFile(fileName, "application/pgp-keys", "Your PGP Key")
	if err != nil {
		return fmt.Errorf("Could not create attachment: %v", err)
	}
	_, err = attachmentWriter.Write(m.Attachment)
	if err != nil {
		return fmt.Errorf("Could not write attachment: %v", err)
	}

	return nil
}
