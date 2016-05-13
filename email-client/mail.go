package emailclient

import (
	"bytes"
	"mime/multipart"
	"net/textproto"
	"time"
)

// MIMEPart represents a MIME section with headers and message
type MIMEPart struct {
	Headers textproto.MIMEHeader
	Message []byte
}

// NewMIMEPart returns an empty MIME section with headers and message
func NewMIMEPart() MIMEPart {
	part := MIMEPart{}
	part.Headers = make(textproto.MIMEHeader)
	return part
}

func checkedWrite(buffer bytes.Buffer, s string) {
	_, err := buffer.WriteString(s)
	if err != nil {
		panic(err)
	}
}

// ConstructEmail constructs an email to the given recipient consisting of the two MIMEParts
func ConstructEmail(recipient string, parts ...MIMEPart) string {
	var mail bytes.Buffer
	multipartWriter := multipart.NewWriter(&mail)
	checkedWrite(mail, "\r\n")
	checkedWrite(mail, "From: Test GPG Validation Server <test-gpg-validation-server@tngtech.com>\r\n")
	checkedWrite(mail, "To: "+recipient+"\r\n")
	checkedWrite(mail, "Date: "+time.Now().Format(time.RFC1123Z)+"\r\n")
	checkedWrite(mail, "Subject: GPG Key Validation\r\n")
	// checkedWrite(mail, "X-Pgp-Agent: github.com/TNG/gpg-validation-server\r\n")
	// In-Reply-To: <5719D0CA.7000609@tngtech.com>
	checkedWrite(mail, "Content-Transfer-Encoding: 7bit\r\n")
	// Message-Id: <77777770-1111-2222-3333-444444444444@tngtech.com>
	// References: <88888888-2222-4232-2321-121312312312@tngtech.com> <12389DDA.0000123@tngtech.com>
	// checkedWrite(mail, "Content-Description: OpenPGP encrypted message\r\n")
	checkedWrite(mail, "X-Mailer: github.com/TNG/gpg-validation-server\r\n")

	// Now follow the MIME Headers
	checkedWrite(mail, "Mime-Version: 1.0 (Golang 1.6)\r\n")
	// checkedWrite(mail, "Content-Type: multipart/encrypted; boundary=\"" + multipartWriter.Boundary() + "\"; protocol=\"application/pgp-encrypted\";\r\n")
	checkedWrite(mail, "Content-Type: multipart/plain; boundary=\""+multipartWriter.Boundary()+"\";\r\n")
	checkedWrite(mail, "\r\n")
	checkedWrite(mail, "This is an OpenPGP/MIME encrypted message (RFC 2440 and 3156)\r\n")

	for _, part := range parts {
		partWriter, _ := multipartWriter.CreatePart(part.Headers)
		_, err := partWriter.Write(part.Message)
		if err != nil {
			panic(err)
		}
	}
	err := multipartWriter.Close()
	if err != nil {
		panic(err)
	}
	return mail.String()
}
