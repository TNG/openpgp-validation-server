package mail

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/TNG/gpg-validation-server/gpg"
	"golang.org/x/net/html/charset"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"reflect"
	"regexp"
	"strings"
)

// MimeEntity describes a multipart MIME encoded message
type MimeEntity struct {
	Header       textproto.MIMEHeader
	Content      []byte
	Parts        []MimeEntity
	IsAttachment bool
	SignedBy     gpg.Key
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
	CheckMessageSignature(message io.Reader, signature io.Reader, checkedSignerKey gpg.Key) error
	ReadKey(r io.Reader) (gpg.Key, error)
}

// Parser parses MIME mails.
type Parser struct {
	Gpg GpgUtility
}

// ParseMail returns a MimeEntity containing the parsed form of the input email
func (parser *Parser) ParseMail(mailReader io.Reader) (*MimeEntity, error) {
	mailInput, err := ioutil.ReadAll(mailReader)
	if err != nil {
		return nil, fmt.Errorf("Cannot read mail input: %s", err)
	}
	mailInput = parser.normalizeNewLines(mailInput)

	message, err := mail.ReadMessage(bytes.NewReader(mailInput))
	if err != nil {
		return nil, fmt.Errorf("Cannot parse mail input: %s", err)
	}
	entity, err := parser.parseEntity(textproto.MIMEHeader(message.Header), message.Body)
	if err != nil {
		return nil, fmt.Errorf("Cannot parse entity: %s", err)
	}
	if entity == nil {
		return nil, errors.New("Cannot parse entity, mail format not supported.")
	}
	return entity, nil
}

// normalizeNewLines converts line endings to the canonical <CR><LF> sequence.
func (parser *Parser) normalizeNewLines(data []byte) []byte {
	regex := regexp.MustCompile("\r?\n")
	return regex.ReplaceAll(data, []byte("\r\n"))
}

func getMimeMediaTypeFromHeader(
	header textproto.MIMEHeader, key string, defaultValue string) (MimeMediaType, error) {
	valueString := header.Get(key)
	if len(valueString) == 0 {
		return MimeMediaType{defaultValue, make(map[string]string)}, nil
	}
	mediatype, params, err := mime.ParseMediaType(valueString)
	if err != nil {
		return MimeMediaType{}, fmt.Errorf("Cannot parse \"%s\" media type \"%s\": %s", key, valueString, err)
	}
	return MimeMediaType{mediatype, params}, nil
}

func (parser *Parser) parseEntity(header textproto.MIMEHeader, body io.Reader) (*MimeEntity, error) {
	contentType, err := getMimeMediaTypeFromHeader(header, "Content-Type", "text/plain")
	if err != nil {
		return nil, fmt.Errorf("Cannot get content type: %s", err)
	}
	contentDisposition, err := getMimeMediaTypeFromHeader(header, "Content-Disposition", "")
	if err != nil {
		return nil, fmt.Errorf("Cannot check content disposition: %s", err)
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
	log.Printf("Ignoring non-attachment content of unknown type '%s'.\n", header.Get("Content-Type"))
	return nil, nil
}

func (parser *Parser) parseText(contentType MimeMediaType, header textproto.MIMEHeader,
	body io.Reader) (*MimeEntity, error) {
	var err error
	charsetLabel, ok := contentType.Params["charset"]
	if ok {
		body, err = charset.NewReaderLabel(charsetLabel, body)
		if err != nil {
			return nil, fmt.Errorf("Cannot read content %s %s: %s", contentType.Value, charsetLabel, err)
		}
	}
	content, err := ioutil.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("Cannot read content body %s %s: %s", contentType.Value, charsetLabel, err)
	}

	return &MimeEntity{
		Header:       header,
		Content:      content,
		Parts:        nil,
		IsAttachment: false,
		SignedBy:     nil}, nil
}

func (parser *Parser) parseMultipart(contentType MimeMediaType, header textproto.MIMEHeader,
	body io.Reader) (*MimeEntity, error) {
	// TODO #9 Error handling.
	boundary, ok := contentType.Params["boundary"]
	if !ok {
		return nil, fmt.Errorf("Multipart mail with type %s has no boundary specified.", contentType.Value)
	}
	result := MimeEntity{
		Header:       header,
		Content:      nil,
		Parts:        make([]MimeEntity, 0),
		IsAttachment: false,
		SignedBy:     nil}

	reader := multipart.NewReader(body, boundary)
	for {
		part, err := reader.NextPart()
		if err != nil {
			if err != io.EOF {
				return nil, fmt.Errorf("Cannot read %s %s: %s", contentType.Value, boundary, err)
			}
			return &result, nil
		}
		entity, err := parser.parseEntity(part.Header, part)
		if err != nil {
			return nil, fmt.Errorf("Cannot parse entity from \"%s\" \"%s\": %s", contentType.Value, boundary, err)
		}
		if entity != nil {
			result.Parts = append(result.Parts, *entity)
		}
	}
}

func (parser *Parser) parseMultipartSigned(contentType MimeMediaType, header textproto.MIMEHeader,
	body io.Reader) (*MimeEntity, error) {
	entity, signerKey, err := parser.parseMultipartSignedWithError(contentType, header, body)

	if entity != nil {
		if err != nil {
			log.Printf("Entity has no valid signature, because: %s\n", err)
		} else {
			entity.SignedBy = signerKey
		}

		return entity, nil
	}

	if err != nil {
		return nil, fmt.Errorf("Multipart could not be parsed: %s", err)
	}

	panic("Unreachable")
}

// Check and parse a signed multipart message according to RFC 3156:
// """
//  The multipart/signed body MUST consist of exactly two parts.  The
//  first part contains the signed data in MIME canonical format,
//  including a set of appropriate content headers describing the data.
//
//  The second body MUST contain the OpenPGP digital signature.  It MUST
//  be labeled with a content type of "application/pgp-signature".
// """
//
// Returns no error, if the signature could be verified.
//
// If an error is returned, the returned entity might either be:
//   - ´nil´: if the multipart could not be parsed at all. // TODO #9 Is this a practical criterion?
//   - inconsistent: In this case, the caller is responsible to discard or correct the returned entity.
//
func (parser *Parser) parseMultipartSignedWithError(contentType MimeMediaType, header textproto.MIMEHeader,
	body io.Reader) (*MimeEntity, gpg.Key, error) {

	_, ok := contentType.Params["micalg"] // TODO #9 How to validate mic algorithm?
	if !ok {
		return nil, nil, errors.New("Multipart/signed mail must specify micalg parameter.")
	}

	buffer := new(bytes.Buffer)
	teeReader := io.TeeReader(body, buffer)
	result, err := parser.parseMultipart(contentType, header, teeReader)
	if err != nil {
		return nil, nil, fmt.Errorf("Cannot parse multipart: %s", err)
	}

	if len(result.Parts) != 2 {
		return result, nil, fmt.Errorf("Multipart/signed body must contain two parts, but got %d.", len(result.Parts))
	}

	boundary, ok := contentType.Params["boundary"]
	if !ok {
		panic("Unreachable, because missing boundary parameter has to be checked before.")
	}

	signedPart := parser.findSignedPart(buffer.Bytes(), boundary)

	signature, err := parser.parseMultipartSignature(result)
	if err != nil {
		return result, nil, fmt.Errorf("Cannot parse signature: %s", err)
	}

	signerKey, err := parser.parseMultipartSignerKey(result)
	if err != nil {
		return result, nil, fmt.Errorf("Cannot parse signer key: %s", err)
	}

	err = parser.Gpg.CheckMessageSignature(bytes.NewReader(signedPart), bytes.NewReader(signature), signerKey)
	if err != nil {
		log.Printf("DEBUG: Error in CheckMessageSignature for primary key with ID %s and identities %+v\n",
			signerKey.PrimaryKey.KeyIdString(), reflect.ValueOf(signerKey.Identities).MapKeys())
		return result, nil, fmt.Errorf("Cannot verify message signature: %s", err)
	}

	return result, signerKey, nil
}

func (parser *Parser) parseMultipartSignerKey(multipart *MimeEntity) (gpg.Key, error) {
	signerKeyAttachment, err := multipart.FindAttachment("application/pgp-keys")
	if err != nil {
		return nil, fmt.Errorf("Cannot find attachment: %s", err)
	}

	signerKey, err := parser.Gpg.ReadKey(bytes.NewReader(signerKeyAttachment))
	if err != nil {
		return nil, fmt.Errorf("Cannot read key: %s", err)
	}

	return signerKey, nil
}

func (parser *Parser) parseMultipartSignature(multipart *MimeEntity) ([]byte, error) {
	signatureHeader, err := getMimeMediaTypeFromHeader(multipart.Parts[1].Header, "Content-Type", "")
	if err != nil {
		log.Panicln("Unreachable, because we already successfully parsed the multipart content", err)
	}
	if signatureHeader.Value != "application/pgp-signature" {
		return nil, fmt.Errorf("Invalid signature content-type '%s'.", signatureHeader)
	}

	signature, err := multipart.FindAttachment("application/pgp-signature")
	if err != nil {
		return nil, fmt.Errorf("Cannot find attachment: %s", err)
	}

	return signature, err
}

func (parser *Parser) findSignedPart(data []byte, boundary string) []byte { // TODO #9 error handling
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
	endOfSignedPart += startOfSignedPart // add correct offset

	regex := regexp.MustCompile("(\r\n)*$")
	index := regex.FindIndex(data[startOfSignedPart:endOfSignedPart]) // don't include trailing \r\n
	endOfSignedPart = startOfSignedPart + index[0]

	return append(data[startOfSignedPart:endOfSignedPart], []byte("\r\n")...)
}

func (parser *Parser) createAttachment(contentDisposition MimeMediaType, header textproto.MIMEHeader,
	body io.Reader) (*MimeEntity, error) {
	data, err := ioutil.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("Cannot read body: %s", err)
	}
	return &MimeEntity{
		Header:       header,
		Content:      data,
		Parts:        nil,
		IsAttachment: true,
		SignedBy:     nil}, nil
}

// FindAttachment returns the first attachment of the given mimeType or an error if none is found.
func (entity *MimeEntity) FindAttachment(mimeType string) ([]byte, error) {
	attachment := entity.findAttachmentOrNil(mimeType)
	if attachment == nil {
		return nil, fmt.Errorf("No attachment of type \"%s\".", mimeType)
	}
	return attachment, nil
}

func (entity *MimeEntity) findAttachmentOrNil(mimeType string) []byte {
	if entity.IsAttachment {
		contentType, _ := getMimeMediaTypeFromHeader(entity.Header, "Content-Type", "")
		if contentType.Value == mimeType {
			return entity.Content
		}
	}
	if entity.Parts != nil {
		for _, part := range entity.Parts {
			attachment := part.findAttachmentOrNil(mimeType)
			if attachment != nil {
				return attachment
			}
		}
	}
	return nil
}
