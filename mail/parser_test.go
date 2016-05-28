package mail

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"net/textproto"
	"os"
	"regexp"
	"strings"
	"testing"
)

func parseMailFromString(source string) (*MimeEntity, error) {
	return parseMailFromStringWithGpg(source, nil)
}

func parseMailFromStringWithGpg(source string, gpg GpgUtility) (*MimeEntity, error) {
	parser := Parser{gpg}
	reader := strings.NewReader(source)
	return parser.ParseMail(reader)
}

func loadTestMail(fileName string) ([]byte, error) {
	input, err := os.Open("../test/mails/" + fileName)
	if err != nil {
		return nil, err
	}
	defer func() { input.Close() }()
	data, err := ioutil.ReadAll(input)
	if err != nil {
		return nil, err
	}
	regex := regexp.MustCompile("\r?\n")
	return regex.ReplaceAll(data, []byte("\r\n")), nil
}

func parseMailFromFile(fileName string) (*MimeEntity, error) {
	return parseMailFromFileWithGpg(fileName, nil)
}

func parseMailFromFileWithGpg(fileName string, gpg GpgUtility) (*MimeEntity, error) {
	data, err := loadTestMail(fileName)
	if err != nil {
		return nil, err
	}
	parser := Parser{gpg}
	return parser.ParseMail(bytes.NewReader(data))
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
	builder.Buffer.WriteString(fmt.Sprintf("--%s\r\n", builder.Boundary))
	if contentType != "" {
		builder.Buffer.WriteString(fmt.Sprintf("Content-Type: %s\r\n", contentType))
	}
	if header != nil {
		for key, values := range header {
			for _, value := range values {
				builder.Buffer.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
			}
		}
	}
	builder.Buffer.WriteString("\r\n")
	builder.Buffer.WriteString(text)
	builder.Buffer.WriteString("\r\n")
	return builder
}

func (builder *MultipartBuilder) build() string {
	builder.Buffer.WriteString(fmt.Sprintf("--%s--\r\n", builder.Boundary))
	return builder.Buffer.String()
}

func TestParseHeaders(t *testing.T) {
	mail, err := parseMailFromFile("plaintext.eml")
	assert.NoError(t, err)
	assert.Equal(t, 8, len(mail.Header))
	assert.Equal(t, "Basic test", mail.Header["Subject"][0])
	assert.Equal(t, "text/plain", mail.Header["Content-Type"][0])
}

func TestParseEmptyMail(t *testing.T) {
	mail, err := parseMailFromString("\r\n")
	assert.NoError(t, err)
	assert.Equal(t, 0, len(mail.Parts))
	assert.Equal(t, 0, len(mail.Header))
	assert.False(t, mail.IsAttachment)
	assert.False(t, mail.IsSigned)
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
	t                                                     *testing.T
	expectedMicAlgorithm, expectedData, expectedSignature string
	checked                                               bool
}

func (gpg *MockGpg) CheckSignature(micAlgorithm string, data []byte, signature []byte) bool {
	assert.Equal(gpg.t, gpg.expectedMicAlgorithm, micAlgorithm)
	assert.Equal(gpg.t, gpg.expectedData, string(data))
	assert.Equal(gpg.t, gpg.expectedSignature, string(signature))
	gpg.checked = true
	return true
}

func TestParseMultipartSigned(t *testing.T) {
	text := createMultipart("frontier").
		withPart("text/plain", "Hello there!", nil).
		withPart("application/pgp-signature", "SIGNATURE", nil).
		build()

	expectedSignedPart := "Content-Type: text/plain\r\n\r\nHello there!\r\n"
	mockGpg := &MockGpg{t, "pgp-sha1", expectedSignedPart, "SIGNATURE", false}
	parser := Parser{mockGpg}
	contentType := MimeMediaType{"multipart/signed", map[string]string{"boundary": "frontier", "micalg": "pgp-sha1"}}
	mail, err := parser.parseMultipartSigned(contentType, textproto.MIMEHeader{}, strings.NewReader(text))
	assert.NoError(t, err)
	assert.True(t, mail.IsSigned)
	assert.True(t, mockGpg.checked)
	assert.Equal(t, 2, len(mail.Parts))
}

func TestPlainText(t *testing.T) {
	mail, err := parseMailFromFile("plaintext.eml")
	assert.NoError(t, err)
	assert.Equal(t, "This is some nice plain text!\r\n", string(mail.Content))
}

func TestMultipartSigned(t *testing.T) {
	signedPart := "Content-Type: text/plain\r\n\r\nHello this is me!\r\n\r\n"
	mockGpg := &MockGpg{t, "pgp-sha1", signedPart, "SIGNATURE", false}
	mail, err := parseMailFromFileWithGpg("signed_multipart_simple.eml", mockGpg)
	assert.NoError(t, err)
	assert.True(t, mockGpg.checked)
	assert.Equal(t, 2, len(mail.Parts))
	assert.True(t, mail.IsSigned)
}

func TestFindAttachment(t *testing.T) {
	mail, err := parseMailFromFile("attachment.eml")
	assert.NoError(t, err)
	data := mail.FindAttachment("application/octet-stream")
	assert.Equal(t, "This is a PDF file.", string(data))
	data = mail.FindAttachment("image/png")
	assert.Nil(t, data)
}
