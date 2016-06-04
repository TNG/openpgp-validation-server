package mail

import (
	"bytes"
	"errors"
	"fmt"
	"golang.org/x/net/html/charset"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"strings"
)

// MimeEntity describes a multi-part MIME encoded message
type MimeEntity struct {
	Header       textproto.MIMEHeader
	Content      []byte
	Parts        []MimeEntity
	IsAttachment bool
	IsSigned     bool
}

// MimeMediaType describes a Media Type with associated parameters
type MimeMediaType struct {
	Value  string
	Params map[string]string
}

func (entity *MimeEntity) getHeader(name, defaultValue string) string {
	canonicalName := textproto.CanonicalMIMEHeaderKey(name)
	values, ok := entity.Header[canonicalName]
	if !ok || len(values) == 0 {
		return defaultValue
	}
	return values[0]
}

func (entity *MimeEntity) getSubject() string {
	return entity.getHeader("Subject", "")
}

// GpgUtility is required by mail.Parser to check signatures and decrypt mails,
type GpgUtility interface {
	CheckSignature(micAlgorithm string, data []byte, signature []byte) bool
}

// Parser parses MIME mails.
type Parser struct {
	Gpg GpgUtility
}

// ParseMail returns a MimeEntity containing the parsed form of the input email
func (parser *Parser) ParseMail(reader io.Reader) (*MimeEntity, error) {
	message, err := mail.ReadMessage(reader)
	if err != nil {
		return nil, fmt.Errorf("Cannot read message: %s", err)
	}
	entity, err := parser.parseEntity(textproto.MIMEHeader(message.Header), message.Body)
	if err != nil {
		return nil, err
	}
	return entity, nil
}

func getMimeMediaTypeFromHeader(
	header textproto.MIMEHeader, key string, defaultValue string) (MimeMediaType, error) {
	values := header.Get(key)
	if len(values) == 0 {
		return MimeMediaType{defaultValue, make(map[string]string)}, nil
	}
	value, params, err := mime.ParseMediaType(values)
	if err != nil {
		return MimeMediaType{}, err
	}
	return MimeMediaType{value, params}, nil
}

func (parser *Parser) parseEntity(header textproto.MIMEHeader, body io.Reader) (*MimeEntity, error) {
	contentType, err := getMimeMediaTypeFromHeader(header, "Content-Type", "text/plain")
	if err != nil {
		return nil, err
	}
	contentDisposition, err := getMimeMediaTypeFromHeader(header, "Content-Disposition", "")
	if err != nil {
		return nil, err
	}
	if contentDisposition.Value == "attachment" {
		return parser.createAttachment(contentDisposition, header, body)
	}
	if strings.HasPrefix(contentType.Value, "text/") || contentType.Value == "application/pgp-signature" {
		return parser.parseText(contentType, header, body)
	}
	if contentType.Value == "multipart/signed" {
		return parser.parseMultipartSigned(contentType, header, body)
	}
	if strings.HasPrefix(contentType.Value, "multipart/") {
		return parser.parseMultipart(contentType, header, body)
	}
	log.Printf("Ignoring non-attachment content of unknown type '%s'\n", header.Get("Content-Type"))
	return nil, nil
}

func (parser *Parser) parseText(contentType MimeMediaType, header textproto.MIMEHeader,
	body io.Reader) (*MimeEntity, error) {
	var err error
	charsetLabel, ok := contentType.Params["charset"]
	if ok {
		body, err = charset.NewReaderLabel(charsetLabel, body)
		if err != nil {
			return nil, err
		}
	}
	content, err := ioutil.ReadAll(body)
	if err != nil {
		return nil, err
	}

	return &MimeEntity{
		Header:       header,
		Content:      content,
		Parts:        nil,
		IsAttachment: false,
		IsSigned:     false}, nil
}

func (parser *Parser) parseMultipart(contentType MimeMediaType, header textproto.MIMEHeader,
	body io.Reader) (*MimeEntity, error) {
	boundary, ok := contentType.Params["boundary"]
	if !ok {
		return nil, errors.New("multipart mail without boundary")
	}
	result := MimeEntity{
		Header:       header,
		Content:      nil,
		Parts:        make([]MimeEntity, 0),
		IsAttachment: false,
		IsSigned:     false}

	reader := multipart.NewReader(body, boundary)
	for {
		part, err := reader.NextPart()
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			return &result, nil
		}
		entity, err := parser.parseEntity(part.Header, part)
		if err != nil {
			return nil, err
		}
		if entity != nil {
			result.Parts = append(result.Parts, *entity)
		}
	}
}

func (parser *Parser) parseMultipartSigned(contentType MimeMediaType, header textproto.MIMEHeader,
	body io.Reader) (*MimeEntity, error) {
	micAlgorithm, ok := contentType.Params["micalg"]
	if !ok {
		return nil, errors.New("multipart/signed mail must specify micalg parameter")
	}
	buffer := new(bytes.Buffer)
	teeReader := io.TeeReader(body, buffer)
	result, err := parser.parseMultipart(contentType, header, teeReader)
	if err != nil {
		return nil, err
	}
	if len(result.Parts) != 2 {
		return nil, errors.New("multipart/signed mail must contain exactly two parts")
	}
	signatureHeader, err := getMimeMediaTypeFromHeader(result.Parts[1].Header, "Content-Type", "")
	if err != nil {
		// Because we already successfully parsed the multipart content, no error should occur here.
		panic("Unreachable")
	}
	if signatureHeader.Value != "application/pgp-signature" {
		return nil, fmt.Errorf("Found invalid signature content-type '%s'.", signatureHeader)
	}

	boundary, _ := contentType.Params["boundary"]
	signedPart := parser.findSignedPart(buffer.Bytes(), boundary)
	signature := result.Parts[1].Content
	result.IsSigned = parser.Gpg.CheckSignature(micAlgorithm, signedPart, signature)
	return result, nil
}

func (parser *Parser) findSignedPart(data []byte, boundary string) []byte {
	delimiter := []byte("--" + boundary + "\r\n")
	startOfSignedPart := bytes.Index(data, delimiter)
	if startOfSignedPart == -1 {
		panic("Did not find start of signed part")
	}
	startOfSignedPart += len(delimiter)

	delimiter = []byte("\r\n--" + boundary)
	endOfSignedPart := bytes.Index(data[startOfSignedPart:], delimiter)
	if endOfSignedPart == -1 {
		panic("Did not find end of signed part")
	}
	endOfSignedPart += startOfSignedPart + 2 // correct index and include \r\n
	return data[startOfSignedPart:endOfSignedPart]
}

func (parser *Parser) createAttachment(contentDisposition MimeMediaType, header textproto.MIMEHeader,
	body io.Reader) (*MimeEntity, error) {
	data, err := ioutil.ReadAll(body)
	if err != nil {
		return nil, err
	}
	return &MimeEntity{
		Header:       header,
		Content:      data,
		Parts:        nil,
		IsAttachment: true,
		IsSigned:     false}, nil
}

// FindAttachment returns the first attachment of the given mimeType or nil if none is found.
func (entity *MimeEntity) FindAttachment(mimeType string) []byte {
	if entity.IsAttachment {
		contentType, _ := getMimeMediaTypeFromHeader(entity.Header, "Content-Type", "")
		if contentType.Value == mimeType {
			return entity.Content
		}
	}
	if entity.Parts != nil {
		for _, part := range entity.Parts {
			attachment := part.FindAttachment(mimeType)
			if attachment != nil {
				return attachment
			}
		}
	}
	return nil
}
