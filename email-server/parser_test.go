package emailserver

import (
	"fmt"
	"strings"
	"testing"
)

var crlf = "\r\n"

func parseMailFromString(source string) (*MimeEntity, error) {
	reader := strings.NewReader(source)
	return parseMail(reader)
}

type MailBuilder struct {
	Headers []string
	Parts []string
}

func createMail() *MailBuilder {
	return &MailBuilder{make([]string, 0), make([]string, 0)}
}

func (builder *MailBuilder) build() string {
	header := ""
	if len(builder.Headers) > 0 {
		header = strings.Join(builder.Headers, crlf) + crlf
	}
	parts := strings.Join(builder.Parts, "")
	return header + crlf + parts
}

func (builder *MailBuilder) withHeader(name, value string) *MailBuilder {
	builder.Headers = append(builder.Headers, fmt.Sprintf("%s: %s", name, value))
	return builder
}

func (builder *MailBuilder) withSubject(subject string) *MailBuilder {
	return builder.withHeader("Subject", subject)
}

func (builder *MailBuilder) withContentType(contentType string) *MailBuilder {
	return builder.withHeader("Content-Type", contentType)
}

func (builder *MailBuilder) withText(text string) *MailBuilder {
	builder.Parts = append(builder.Parts, text)
	return builder
}

func (builder *MailBuilder) withMultipart(boundary, text string) *MailBuilder {
	return builder.withText(fmt.Sprintf("--%s\r\n\r\n%s\r\n", boundary, text))
}

func (builder *MailBuilder) withFinalMultipartBoundary(boundary string) *MailBuilder {
	return builder.withText(fmt.Sprintf("--%s--\r\n", boundary))
}

func (builder *MailBuilder) withFinalMultipart(boundary, text string) *MailBuilder {
	return builder.withMultipart(boundary, text).withFinalMultipartBoundary(boundary)
}

func (builder *MailBuilder) withMultipartWithHeader(
		boundary string, Header map[string][]string, text string) *MailBuilder {
	headerLines := make([]string, 0, len(Header))
	for name, values := range Header {
		for _, value := range values {
			headerLines = append(headerLines, fmt.Sprintf("%s: %s\r\n", name, value))
		}
	}
	headerSection := strings.Join(headerLines, "")
	return builder.withText(fmt.Sprintf("--%s\r\n%s\r\n%s\r\n", boundary, headerSection, text))
}

func TestParseHeaders(t *testing.T) {
	mailString := createMail().
		withSubject("Test").
		withHeader("MyHeader", "value1").
		withHeader("MyHeader", "value2").
		build()
	mail, err := parseMailFromString(mailString)
	if err != nil {
		t.Error("Error while parsing mail", err)
	}
	if mail.getSubject() != "Test" {
		t.Error("Expected subject 'Test', got", mail.getSubject())
	}
	if mail.getHeader("MyHeader", "") != "value1" {
		t.Error("Expected header 'value1', got", mail.getHeader("MyHeader", ""))
	}
}

func TestParseEmptyMail(t *testing.T) {
	mail, err := parseMailFromString(crlf)
	if err != nil {
		t.Error("Error while parsing mail", err)
	}
	if len(mail.Parts) > 0 || len(mail.Header) > 0 || mail.Attachment != nil {
		t.Error("Expected an empty mail.")
		fmt.Printf("%d %d\n", len(mail.Parts), len(mail.Parts[0].Text))
	}
}

func TestTextPlain(t *testing.T) {
	mailString := createMail().withText("Hello there!").build()
	mail, err := parseMailFromString(mailString)
	if err != nil {
		t.Error("Error while parsing mail", err)
	}
	if mail.Text != "Hello there!" {
		t.Error("Expected text 'Hello there!', got", mail.Parts[0].Text)
	}
	if len(mail.Parts) > 0 || mail.Attachment != nil {
		t.Error("Must not find a subpart or attachment in a plain text mail.")
	}
}

func TestMultipartSinglePart(t *testing.T) {
	mailString := createMail().
		withContentType("multipart/mixed;boundary=\"frontier\"").
		withFinalMultipart("frontier", "Hello there!").
		build()
	mail, err := parseMailFromString(mailString)
	if err != nil {
		t.Error("Error while parsing a multipart mail:", err)
	}
	if len(mail.Text) > 0 || mail.Attachment != nil {
		t.Error("Must not set text or attachment when reading a multipart mail")
	}
	if len(mail.Parts) != 1 || mail.Parts[0].Text != "Hello there!" {
		t.Errorf("Expected exactly one part with text 'Hello there!', got '%v'", mail.Parts)
	}
}

func TestMultipartSeveralParts(t *testing.T) {
	mailString := createMail().
		withContentType("multipart/mixed;boundary=\"frontier\"").
		withMultipart("frontier", "Hello there!").
		withMultipart("frontier", "What's up?").
		withFinalMultipart("frontier", "Bye.").
		build()
	mail, err := parseMailFromString(mailString)
	if err != nil {
		t.Error("Error while parsing a multipart mail:", err)
	}
	if len(mail.Text) > 0 || mail.Attachment != nil {
		t.Error("Must not set text or attachment when reading a multipart mail")
	}
	if len(mail.Parts) != 3 ||
		mail.Parts[0].Text != "Hello there!" ||
		mail.Parts[1].Text != "What's up?" ||
		mail.Parts[2].Text != "Bye." {
		t.Errorf("Got unexpected mail part(s): '%v'", mail.Parts)
	}
}

func TestMultipartNested(t *testing.T) {
	nestedHeader := map[string][]string{"Content-Type": []string{"multipart/mixed;boundary=\"nested\""}}
	mailString := createMail().withContentType("multipart/mixed;boundary=\"frontier\"").
		withMultipartWithHeader("frontier", nestedHeader, "").
		withFinalMultipart("nested", "This is a nested message.").
		withFinalMultipartBoundary("frontier").
		build()
	mail, err := parseMailFromString(mailString)
	if err != nil {
		t.Error("Error while parsing a multipart mail:", err)
	}
	if len(mail.Text) > 0 || mail.Attachment != nil {
		t.Error("Must not set text or attachment when reading a multipart mail")
	}
	if len(mail.Parts) != 1 || len(mail.Parts[0].Text) > 0 || len(mail.Parts[0].Parts) != 1 {
		t.Errorf("Expected exactly one nested part, got: %v", mail.Parts)
	}
	if mail.Parts[0].Parts[0].Text != "This is a nested message." {
		t.Errorf("Expected text 'This is a nested message.', got '%s'.", mail.Parts[0].Parts[0].Text)
	}
}

func TestInvalidContentType(t *testing.T) {
	// second value is missing the boundary
	invalidContentTypes := []string{"text/", "multipart/mixed;"}
	for _, contentType := range invalidContentTypes {
		mailString := createMail().withContentType(contentType).build()
		mail, err := parseMailFromString(mailString)
		if err == nil || mail != nil {
			t.Error("Expected an error when parsing mail with invalid content type")
		}
	}
}

func TestNonAsciiChars(t *testing.T) {
	// RFC 2045 requires that a Content-Transfer-Encoding (e.g. 8bit) is specified,
	// However, for robustness this should also work without.
	mailString := createMail().
		withContentType("text/plain; charset=ISO-8859-15").
		withText("\xe0\x20\x63\xf4\x74\xe9").
		build()
	mail, err := parseMailFromString(mailString)
	if err != nil {
		t.Error("Error while parsing a mail:", err)
	}
	if mail.Text != "à côté" {
		t.Error("Expected: 'à côté', got", mail.Text)
	}
}

func TestQuotedPrintableInMultipart(t *testing.T) {
	// Should work out of the box, because mime/multipart handles this
	partHeader := map[string][]string{
		"Content-Type": []string{"text/plain; charset=ISO-8859-15"},
		"Content-Transfer-Encoding": []string{"quoted-printable"},
	}
	mailString := createMail().
		withContentType("multipart/mixed;boundary=\"frontier\"").
		withMultipartWithHeader("frontier", partHeader, "B=E4renf=FC=DFe").
		withFinalMultipartBoundary("frontier").
		build()
	mail, err := parseMailFromString(mailString)
	if err != nil {
		t.Error("Error while parsing a mail:", err)
	}
	if mail.Parts[0].Text != "Bärenfüße" {
		t.Error("Expected: 'Bärenfüße', got", mail.Parts[0].Text)
	}
}

func TestAttachment(t *testing.T) {
	partHeader := map[string][]string{
		"Content-Type": []string{"application/octet-stream"},
		"Content-Disposition": []string{"attachment; filename=\"test.pdf\""},
	}
	mailString := createMail().
		withContentType("multipart/mixed;boundary=\"frontier\"").
		withMultipartWithHeader("frontier", partHeader, "Pizza").
		withFinalMultipartBoundary("frontier").
		build()
	mail, err := parseMailFromString(mailString)
	if err != nil {
		t.Error("Error while parsing a mail:", err)
	}
	if string(mail.Parts[0].Attachment) != "Pizza" {
		t.Error("Expected attachment 'Pizza', got", string(mail.Parts[0].Attachment))
	}
	if len(mail.Parts[0].Text) > 0 || len(mail.Parts[0].Parts) > 0 {
		t.Error("Must not set text or parts for an attachment.")
	}
}
