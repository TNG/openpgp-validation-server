package mail

import (
	"bytes"
	"fmt"
	"github.com/TNG/openpgp-validation-server/gpg"
	"github.com/TNG/openpgp-validation-server/test/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/openpgp"
	"io"
	"io/ioutil"
	"net/textproto"
	"strings"
	"testing"
)

func parseMailFromString(t *testing.T, source string) *MimeEntity {
	return parseMailFromStringWithGpg(t, source, nil)
}

func parseMailFromStringWithGpg(t *testing.T, source string, gpg GpgUtility) *MimeEntity {
	parser := Parser{gpg}
	reader := strings.NewReader(source)
	entity, err := parser.ParseMail(reader)
	assert.NoError(t, err, "Unexpected error in ParseMail!")
	return entity
}

func loadTestMail(t *testing.T, fileName string) []byte {
	input, cleanup := utils.Open(t, "../test/mails/"+fileName)
	defer cleanup()
	data, err := ioutil.ReadAll(input)
	require.NoError(t, err)
	return data
}

func parseMailFromFile(t *testing.T, fileName string) *MimeEntity {
	return parseMailFromFileWithGpg(t, fileName, nil)
}

func parseMailFromFileWithGpg(t *testing.T, fileName string, gpg GpgUtility) *MimeEntity {
	data := loadTestMail(t, fileName)
	parser := Parser{gpg}
	entity, err := parser.ParseMail(bytes.NewReader(data))
	require.NoError(t, err, "Unexpected error in ParseMail!")
	return entity
}

type MultipartBuilder struct {
	Boundary string
	Buffer   bytes.Buffer
}

func createMultipart(boundary string) *MultipartBuilder {
	return &MultipartBuilder{Boundary: boundary}
}

func (builder *MultipartBuilder) withPart(contentType string,
	text string, header textproto.MIMEHeader) *MultipartBuilder {
	_, _ = builder.Buffer.WriteString(fmt.Sprintf("--%s\r\n", builder.Boundary))
	if contentType != "" {
		_, _ = builder.Buffer.WriteString(fmt.Sprintf("Content-Type: %s\r\n", contentType))
	}
	if header != nil {
		for key, values := range header {
			for _, value := range values {
				_, _ = builder.Buffer.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
			}
		}
	}
	_, _ = builder.Buffer.WriteString("\r\n")
	_, _ = builder.Buffer.WriteString(text)
	_, _ = builder.Buffer.WriteString("\r\n")
	return builder
}

func (builder *MultipartBuilder) withAttachment(contentType string, text string) *MultipartBuilder {
	header := textproto.MIMEHeader{}
	header.Set("Content-Disposition", "attachment")
	builder.withPart(contentType, text, header)
	return builder
}

func (builder *MultipartBuilder) build() string {
	_, _ = builder.Buffer.WriteString(fmt.Sprintf("--%s--\r\n", builder.Boundary))
	return builder.Buffer.String()
}

func TestGetMimeMediaTypeFromHeader(t *testing.T) {
	header := textproto.MIMEHeader{"Content-Type": {"foo; param=bar", "stuff"}}
	mediaType := getMimeMediaType(header, "Content-Type")
	assert.Equal(t, "foo", mediaType.Value)
	assert.Equal(t, 1, len(mediaType.Params))
	assert.Equal(t, "bar", mediaType.Params["param"])
	mediaType = getMimeMediaType(header, "key")
	assert.Equal(t, "", mediaType.Value)
}

func TestParseHeaders(t *testing.T) {
	mail := parseMailFromFile(t, "plaintext.eml")
	assert.Equal(t, 8, len(mail.Header))
	assert.Equal(t, "Basic test", mail.Header["Subject"][0])
	assert.Equal(t, "text/plain", mail.Header["Content-Type"][0])
}

func TestParseEmptyMail(t *testing.T) {
	mail := parseMailFromString(t, "\r\n")
	assert.Equal(t, 0, len(mail.Parts))
	assert.Equal(t, 0, len(mail.Header))
	assert.False(t, mail.IsAttachment)
	assert.Nil(t, mail.SignedBy)
}

func TestParseText(t *testing.T) {
	parser := &Parser{Gpg: nil}
	contentType := MimeMediaType{"text/plain", nil}
	header := textproto.MIMEHeader{}
	entity, err := parser.parseText(contentType, header, strings.NewReader("Hello world!"))
	assert.NoError(t, err)
	assert.Equal(t, "Hello world!", string(entity.Content))
}

func TestParseTextWithCharset(t *testing.T) {
	parser := &Parser{Gpg: nil}
	contentType := MimeMediaType{"text/plain", map[string]string{"charset": "ISO-8859-1"}}
	header := textproto.MIMEHeader{}
	entity, err := parser.parseText(contentType, header, strings.NewReader("\xe0\x20\x63\xf4\x74\xe9"))
	assert.NoError(t, err)
	assert.Equal(t, "à côté", string(entity.Content))
}

func TestParseTextWithInvalidEncoding(t *testing.T) {
	parser := &Parser{Gpg: nil}
	contentType := MimeMediaType{"text/plain", map[string]string{"charset": "utf-8"}}
	header := textproto.MIMEHeader{}
	entity, err := parser.parseText(contentType, header, bytes.NewReader([]byte{0xC0}))
	assert.Nil(t, err)
	assert.Equal(t, "\uFFFD", string(entity.Content))
}

func TestParseMultipart(t *testing.T) {
	parser := &Parser{Gpg: nil}
	contentType := MimeMediaType{"multipart/mixed", map[string]string{"boundary": "frontier"}}
	header := textproto.MIMEHeader{}
	text := createMultipart("frontier").
		withPart("text/plain", "Part0", nil).
		withPart("text/plain", "Part1", nil).
		withPart("text/plain", "Part2", nil).
		build()
	entity, err := parser.parseMultipart(contentType, header, strings.NewReader(text))
	assert.NoError(t, err)
	assert.Equal(t, 3, len(entity.Parts))
	assert.Equal(t, "Part0", string(entity.Parts[0].Content))
	assert.Equal(t, "Part1", string(entity.Parts[1].Content))
	assert.Equal(t, "Part2", string(entity.Parts[2].Content))
}

func TestParseMultipartWithoutBoundary(t *testing.T) {
	parser := &Parser{Gpg: nil}
	contentType := MimeMediaType{"multipart/mixed", map[string]string{}}
	header := textproto.MIMEHeader{}
	text := createMultipart("frontier").withPart("text/plain", "Hello world!", nil).build()
	entity, err := parser.parseMultipart(contentType, header, strings.NewReader(text))
	assert.NotNil(t, err)
	assert.Nil(t, entity)
}

func TestParseMultipartNested(t *testing.T) {
	parser := &Parser{Gpg: nil}
	contentType := MimeMediaType{"multipart/mixed", map[string]string{"boundary": "frontier"}}
	header := textproto.MIMEHeader{}
	inner := createMultipart("inner").withPart("text/plain", "Nested text", nil).build()
	text := createMultipart("frontier").
		withPart("multipart/mixed; boundary=inner", inner, nil).
		build()
	entity, err := parser.parseMultipart(contentType, header, strings.NewReader(text))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(entity.Parts))
	innerPart := entity.Parts[0]
	assert.Equal(t, 1, len(innerPart.Header))
	assert.Equal(t, "multipart/mixed; boundary=inner", innerPart.Header.Get("Content-Type"))
	assert.Equal(t, 1, len(innerPart.Parts))
	assert.Equal(t, "Nested text", string(innerPart.Parts[0].Content))
}

func TestParseMultipartInvalid(t *testing.T) {
	parser := &Parser{Gpg: nil}
	contentType := MimeMediaType{"multipart/mixed", map[string]string{"boundary": "frontier"}}
	header := textproto.MIMEHeader{}
	text := createMultipart("frontier").
		withPart("text/plain", "Hello", nil).
		build()
	text = text[:len(text)-4] // Remove final boundary end '--' (and \r\n).
	entity, err := parser.parseMultipart(contentType, header, strings.NewReader(text))
	assert.Nil(t, entity)
	assert.NotNil(t, err)
}

func TestParseMultipartWithQuotedPrintable(t *testing.T) {
	parser := &Parser{Gpg: nil}
	contentType := MimeMediaType{"multipart/mixed", map[string]string{"boundary": "frontier"}}
	header := textproto.MIMEHeader{}
	innerHeader := textproto.MIMEHeader{}
	innerHeader.Set("Content-Type", "text/plain; charset=ISO-8859-1")
	innerHeader.Set("Content-Transfer-Encoding", "quoted-printable")
	text := createMultipart("frontier").withPart("", "B=E4renf=FC=DFe", innerHeader).build()
	entity, err := parser.parseMultipart(contentType, header, strings.NewReader(text))
	assert.NoError(t, err)
	assert.Equal(t, "Bärenfüße", string(entity.Parts[0].Content))
}

type MockGpg struct {
	t                                  *testing.T
	expectedMessage, expectedSignature string
	checked                            bool
}

func (mockGpg *MockGpg) CheckMessageSignature(message io.Reader, signature io.Reader, checkedSignerKey gpg.Key) error {
	messageData, _ := ioutil.ReadAll(message)
	signatureData, _ := ioutil.ReadAll(signature)

	assert.Equal(mockGpg.t, mockGpg.expectedMessage, string(messageData))
	assert.Equal(mockGpg.t, mockGpg.expectedSignature, string(signatureData))
	mockGpg.checked = true
	return nil
}

func (mockGpg *MockGpg) ReadKey(r io.Reader) (gpg.Key, error) {
	// TODO #9 actually check something here
	return openpgp.NewEntity("mock", "", "mock@server.local", nil)
}

func (mockGpg *MockGpg) EncryptMessage(output io.Writer, recipientKey gpg.Key) (plaintext io.WriteCloser, err error) {
	panic("Don't call me here!")
}

func (mockGpg *MockGpg) DecryptMessage(message io.Reader) (result io.Reader, err error) {
	panic("Don't call me here!")
}

func (mockGpg *MockGpg) DecryptSignedMessage(message io.Reader, output io.Writer, signerKey gpg.Key) error {
	panic("Don't call me here!")
}

func TestParseMultipartSigned(t *testing.T) {
	innerText := createMultipart("innerBoundary").
		withPart("text/plain", "Hello there!", nil).
		withAttachment("application/pgp-keys", "KEYS").
		build()

	text := createMultipart("frontier").
		withPart("multipart/mixed; boundary=\"innerBoundary\"", innerText, nil).
		withAttachment("application/pgp-signature", "SIGNATURE").
		build()
	t.Log(text)
	expectedSignedPart := "Content-Type: multipart/mixed; boundary=\"innerBoundary\"\r\n" +
		"\r\n" +
		"--innerBoundary\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Hello there!\r\n" +
		"--innerBoundary\r\n" +
		"Content-Type: application/pgp-keys\r\n" +
		"Content-Disposition: attachment\r\n" +
		"\r\n" +
		"KEYS\r\n" +
		"--innerBoundary--\r\n"
	mockGpg := &MockGpg{t, expectedSignedPart, "SIGNATURE", false}
	parser := Parser{mockGpg}
	contentType := MimeMediaType{"multipart/signed", map[string]string{"boundary": "frontier", "micalg": "pgp-sha1"}}
	mail, err := parser.parseMultipartSigned(contentType, textproto.MIMEHeader{}, strings.NewReader(text))
	assert.NoError(t, err)
	require.NotNil(t, mail, "Mail can be parsed.")
	assert.NotNil(t, mail.SignedBy)
	assert.True(t, mockGpg.checked)
	assert.Equal(t, 2, len(mail.Parts))
}

func TestPlainText(t *testing.T) {
	mail := parseMailFromFile(t, "plaintext.eml")
	assert.Equal(t, "This is some nice plain text!\r\n", string(mail.Content))
}

// TODO #6 Do we support signed mail parsing that do not contain a public key attachment?
//func TestMultipartSigned(t *testing.T) {
//	signedPart := "Content-Type: text/plain\r\n\r\nHello this is me!\r\n\r\n"
//	mockGpg := &MockGpg{t, signedPart, "SIGNATURE", false}
//	mail := parseMailFromFileWithGpg(t, "signed_multipart_simple.eml", mockGpg)
//	assert.True(t, mockGpg.checked)
//	assert.Equal(t, 2, len(mail.Parts))
//	assert.NotFil(t, mail.SignedBy)
//}

func TestFindAttachment(t *testing.T) {
	mail := parseMailFromFile(t, "attachment.eml")

	data, err := mail.FindAttachment("application/octet-stream")
	assert.NoError(t, err)
	assert.Equal(t, "This is a PDF file.", string(data))

	data, err = mail.FindAttachment("image/png")
	assert.Error(t, err)
	assert.Nil(t, data)
}
