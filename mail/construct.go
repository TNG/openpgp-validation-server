package mail

import (
	"bytes"
	"io"
	"time"
)

// MessageEncrypter is a struct able to sign a message and encrypt it for the recipient key
type MessageEncrypter interface {
	EncryptMessage(output io.Writer, recipientKey io.Reader) (plaintext io.WriteCloser, err error)
}

// OutgoingMail describes the contents of the mail to be sent (WIP)
type OutgoingMail struct {
	Message        string
	RecipientEmail string
	RecipientKey   []byte
	Attachment     []byte
	GPG            MessageEncrypter
}

// Bytes returns the given message as an OpenPGP/MIME encrypted and signed message (RFC 2440 and 3156)
func (m OutgoingMail) Bytes() []byte {
	w := bytes.Buffer{}
	now := time.Now()
	empw := NewEncodingMultipartWriter(&w, "encrypted", "application/pgp-encrypted", map[string]string{
		"Date":                now.Format(time.RFC1123Z),
		"From":                "Test GPG Validation Server <test-gpg-validation-server@tngtech.com>",
		"To":                  m.RecipientEmail,
		"Message-ID":          now.Format(time.RFC3339Nano) + "@gpg-validation.tngtech.com>",
		"Subject":             "GPG Key Validation",
		"X-Mailer":            "github.com/TNG/gpg-validation-server",
		"Content-Description": "OpenPGP encrypted message",
	})
	err := empw.WritePGPMIMEVersion()
	if err != nil {
		panic(err)
	}
	partWriter, err := empw.WriteInlineFile("encrypted.asc", "application/octet-stream", "OpenPGP encrypted message")
	if err != nil {
		panic(err)
	}
	plaintext, err := m.GPG.EncryptMessage(partWriter, bytes.NewBuffer(m.RecipientKey))
	if err != nil {
		panic(err)
	}
	encryptedMultipartWriter := NewEncodingMultipartWriter(plaintext, "mixed", "", nil)
	err = encryptedMultipartWriter.WritePlainText(m.Message)
	if err != nil {
		panic(err)
	}

	encryptedKeyWriter, err := encryptedMultipartWriter.WriteAttachedFile("your_key.asc", "application/pgp-keys", "Your PGP Key")
	if err != nil {
		panic(err)
	}
	_, err = encryptedKeyWriter.Write(m.RecipientKey)
	if err != nil {
		panic(err)
	}
	err = encryptedMultipartWriter.Close()
	if err != nil {
		panic(err)
	}
	err = plaintext.Close()
	if err != nil {
		panic(err)
	}
	err = empw.Close()
	if err != nil {
		panic(err)
	}
	return w.Bytes()
}
