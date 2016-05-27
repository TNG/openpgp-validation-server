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
	assert.NoError(mpw.Close())
	entity, err := ParseMail(buf) // TODO: Check contents of entity
	assert.NoError(err)
	log.Println(entity)
}

func TestExtraHeader(t *testing.T) {
	assert := assert.New(t)
	buf := bytes.NewBuffer([]byte{})
	mpw := NewEncodingMultipartWriter(buf, "mixed", "", map[string]string{
		"X-Header": "extra",
	})
	assert.NoError(mpw.Close())
	entity, err := ParseMail(buf) // TODO: Check contents of entity
	assert.NoError(err)
	log.Println(entity)
}

func TestMultiPart(t *testing.T) {
	assert := assert.New(t)
	buf := bytes.NewBuffer([]byte{})
	mpw := NewEncodingMultipartWriter(buf, "mixed", "", map[string]string{
		"X-Header": "extra",
	})
	assert.NoError(mpw.WritePlainText("This is text/plain\nWith newlines."))
	assert.NoError(mpw.WritePGPMIMEVersion())

	writer, err := mpw.WriteInlineFile("test.txt", "text/plain", "Test file")
	assert.NoError(err)
	_, err = writer.Write([]byte("Content of test file"))
	assert.NoError(err)

	writer, err = mpw.WriteAttachedFile("attached-test.txt", "text/plain", "Attached Test file")
	assert.NoError(err)
	_, err = writer.Write([]byte("Content of attached test file"))
	assert.NoError(err)

	assert.NoError(mpw.Close())
	entity, err := ParseMail(buf) // TODO: Check contents of entity
	assert.NoError(err)
	log.Println(entity)
}
