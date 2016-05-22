package mail

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/textproto"
	"time"
)

// EncryptAndSigner is a struct able to sign a message and encrypt it for the recipient key
type EncryptAndSigner interface {
	EncryptAndSign(ciphertext io.Writer, recipientKey io.Reader) (plaintext io.WriteCloser, err error)
}

// OutgoingMail describes the contents of the mail to be sent (WIP)
type OutgoingMail struct {
	Message        string
	RecipientEmail string
	RecipientKey   []byte
	Attachment     []byte
	GPG            EncryptAndSigner
}

// Bytes returns the given message as an OpenPGP/MIME encrypted and signed message (RFC 2440 and 3156)
func (m OutgoingMail) Bytes() []byte {
	w := bytes.Buffer{}
	multipartWriter := multipart.NewWriter(&w)
	newline := "\r\n"
	now := time.Now()
	header := "Date: " + now.Format(time.RFC1123Z) + newline +
		"From: Test GPG Validation Server <test-gpg-validation-server@tngtech.com>" + newline +
		"To: " + m.RecipientEmail + newline +
		"Message-ID: " + now.Format(time.RFC3339Nano) + "@gpg-validation.tngtech.com>" + newline +
		"Subject: GPG Key Validation" + newline +
		"X-Mailer: github.com/TNG/gpg-validation-server" + newline +
		"Mime-Version: 1.0" + newline +
		"Content-Type: multipart/encrypted;" + newline +
		" boundary=\"" + multipartWriter.Boundary() + "\";" + newline +
		" protocol=\"application/pgp-encrypted\";" + newline +
		"Content-Transfer-Encoding: 7bit" + newline +
		"Content-Description: OpenPGP encrypted message" + newline +
		newline
	_, err := w.Write([]byte(header))
	if err != nil {
		panic(err)
	}

	partWriter, err := multipartWriter.CreatePart(textproto.MIMEHeader{
		"Content-Type":        {"application/pgp-encrypted"},
		"Content-Description": {"PGP/MIME version identification"},
	})
	if err != nil {
		panic(err)
	}
	_, err = partWriter.Write([]byte("Version: 1" + newline))
	if err != nil {
		panic(err)
	}

	partWriter, err = multipartWriter.CreatePart(textproto.MIMEHeader{
		"Content-Type":        {"application/octet-stream; name=\"encrypted.asc\""},
		"Content-Disposition": {"inline; filename=\"encrypted.asc\""},
		"Content-Description": {"OpenPGP encrypted message"},
	})
	if err != nil {
		panic(err)
	}
	plaintext, err := m.GPG.EncryptAndSign(&w, bytes.NewBuffer(m.RecipientKey))
	if err != nil {
		panic(err)
	}
	_, err = plaintext.Write([]byte(m.Message))
	if err != nil {
		panic(err)
	}
	err = plaintext.Close()
	if err != nil {
		panic(err)
	}
	err = multipartWriter.Close()
	if err != nil {
		panic(err)
	}
	return w.Bytes()
}
