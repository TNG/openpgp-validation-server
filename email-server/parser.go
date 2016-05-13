package emailserver

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"golang.org/x/net/html/charset"
	"log"
	"strings"
)

// MimeEntity describes a multi-part MIME encoded message
type MimeEntity struct {
	Header textproto.MIMEHeader
	Text string
	Parts []MimeEntity
	Attachment []byte
}

type MimeMediaType struct {
	Value string
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

func parseMail(reader io.Reader) (*MimeEntity, error) {
	message, err := mail.ReadMessage(reader)
	if err != nil {
		return nil, fmt.Errorf("Cannot read message: %s", err)
	}
	entity, err := parseEntity(textproto.MIMEHeader(message.Header), message.Body)
	if err != nil {
		return nil, err
	}
	return entity, nil
}

func getMimeMediaTypeFromHeader(
		header textproto.MIMEHeader, key string, defaultValue string) (*MimeMediaType, error) {
	values := header.Get(key)
	if len(values) == 0 {
		return &MimeMediaType{defaultValue, make(map[string]string)}, nil
	}
	value, params, err := mime.ParseMediaType(values)
	if err != nil {
		return nil, err
	}
	return &MimeMediaType{value, params}, nil
}

func parseEntity(header textproto.MIMEHeader, body io.Reader) (*MimeEntity, error) {
	contentType, err := getMimeMediaTypeFromHeader(header, "Content-Type", "text/plain")
	if err != nil {
		return nil, err
	}
	contentDisposition, err := getMimeMediaTypeFromHeader(header, "Content-Disposition", "")
	if err != nil {
		return nil, err
	}
	if contentDisposition.Value == "attachment" {
		return createAttachment(contentDisposition, header, body)
	}
	if strings.HasPrefix(contentType.Value, "text/") {
		return parseText(contentType, header, body)
	}
	if strings.HasPrefix(contentType.Value, "multipart/") {
		return parseMultipart(contentType, header, body)
	}
	log.Printf("Ignoring non-attachment content of unknown type '%s'\n", header.Get("Content-Type"))
	return nil, nil
}

func parseText(contentType *MimeMediaType, header textproto.MIMEHeader,
		body io.Reader) (*MimeEntity, error) {
	charsetLabel, ok := contentType.Params["charset"]
	var err error
	if ok {
		body, err = charset.NewReaderLabel(charsetLabel, body)
		if err != nil {
			return nil, err
		}
	}
	text, err := ioutil.ReadAll(body)
	if err != nil {
		return nil, err
	}
	return &MimeEntity{header, string(text), nil, nil}, nil
}

func parseMultipart(contentType *MimeMediaType, header textproto.MIMEHeader,
		body io.Reader) (*MimeEntity, error) {
	boundary, ok := contentType.Params["boundary"]
	if !ok {
		return nil, errors.New("multipart mail without boundary")
	}
	result := MimeEntity{header, "", make([]MimeEntity, 0), nil}

	reader := multipart.NewReader(body, boundary)
	for {
		part, err := reader.NextPart()
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			return &result, nil
		}
		entity, err := parseEntity(part.Header, part)
		if err != nil {
			return nil, err
		}
		if entity != nil {
			result.Parts = append(result.Parts, *entity)
		}
	}
}

func createAttachment(contentDisposition *MimeMediaType, header textproto.MIMEHeader,
		body io.Reader) (*MimeEntity, error) {
	data, err := ioutil.ReadAll(body)
	if err != nil {
		return nil, err
	}
	return &MimeEntity{header, "", nil, data}, nil
}
