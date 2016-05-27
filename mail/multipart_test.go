package mail

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"log"
	"testing"
)

func TestEmptyMultipartWriter(t *testing.T) {
	assert := assert.New(t)
	buf := bytes.NewBuffer([]byte{})
	mpw := NewEncodingMultipartWriter(buf, "mixed", "", nil)
	assert.Nil(mpw.Close())
	entity, err := ParseMail(buf) // TODO: Check contents of entity
	assert.Nil(err)
	log.Println(entity)
}

func TestExtraHeader(t *testing.T) {
	assert := assert.New(t)
	buf := bytes.NewBuffer([]byte{})
	mpw := NewEncodingMultipartWriter(buf, "mixed", "", map[string]string{
		"X-Header": "extra",
	})
	assert.Nil(mpw.Close())
	entity, err := ParseMail(buf) // TODO: Check contents of entity
	assert.Nil(err)
	log.Println(entity)
}

func TestMultiPart(t *testing.T) {
	assert := assert.New(t)
	buf := bytes.NewBuffer([]byte{})
	mpw := NewEncodingMultipartWriter(buf, "mixed", "", map[string]string{
		"X-Header": "extra",
	})
	assert.Nil(mpw.WritePlainText("This is text/plain\nWith newlines."))
	assert.Nil(mpw.WritePGPMIMEVersion())

	writer, err := mpw.WriteInlineFile("test.txt", "text/plain", "Test file")
	assert.Nil(err)
	_, err = writer.Write([]byte("Content of test file"))
	assert.Nil(err)

	writer, err = mpw.WriteAttachedFile("attached-test.txt", "text/plain", "Attached Test file")
	assert.Nil(err)
	_, err = writer.Write([]byte("Content of attached test file"))
	assert.Nil(err)

	assert.Nil(mpw.Close())
	entity, err := ParseMail(buf) // TODO: Check contents of entity
	assert.Nil(err)
	log.Println(entity)
}
