package emailserver

import (
	"io"
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"io/ioutil"
	"net/textproto"
	"golang.org/x/net/html/charset"
)

type MimeEntity struct {
	Header textproto.MIMEHeader
	Text string
	Parts []MimeEntity
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

func getContentType(header textproto.MIMEHeader) (string, map[string]string, error) {
	contentType := header.Get("Content-Type")
	if len(contentType) == 0 {
		return "text/plain", nil, nil
	}
	contentType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", nil, err
	}
	return contentType, params, nil
}

func parseEntity(header textproto.MIMEHeader, body io.Reader) (*MimeEntity, error) {
	contentType, params, err := getContentType(header)
	if err != nil {
		return nil, err
	}

	if strings.HasPrefix(contentType, "text") {
		return parseText(header, body, params)
	}
	if strings.HasPrefix(contentType, "multipart/") {
		return parseMultipart(header, body, params)
	}
	return nil, fmt.Errorf("Unknown mail content type: %s", contentType)
}

func parseText(header textproto.MIMEHeader, body io.Reader, params map[string]string) (*MimeEntity, error) {
	charsetLabel, ok := params["charset"]
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
	return &MimeEntity{header, string(text), nil}, nil
}

func parseMultipart(
		header textproto.MIMEHeader, body io.Reader, params map[string]string) (*MimeEntity, error) {
	boundary, ok := params["boundary"]
	if !ok {
		return nil, errors.New("multipart mail without boundary")
	}
	result := MimeEntity{header, "", make([]MimeEntity, 0)}

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
		result.Parts = append(result.Parts, *entity)
	};
}
