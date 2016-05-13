package mail

import (
	"testing"
)

func TestConstructEmail(t *testing.T) {
	part1 := NewMIMEPart()
	part1.Headers.Add("Content-Type", "text/plain")
	part1.Headers.Add("Content-Description", "Message")
	part1.Message = []byte("This is a mail with an attachment.\r\n")

	part2 := NewMIMEPart()
	part2.Headers.Add("Content-Type", "application/octet-stream")
	part2.Headers.Add("Content-Description", "Attachment")
	part2.Headers.Add("Content-Transfer-Encoding", "7bit")
	part2.Headers.Add("Content-Disposition", "inline;\r\n    filename=\"test.txt\"")
	part2.Message = []byte("Attachment! With other line endings.\n")
	ConstructEmail("recipient@localhost.local", part1, part2)
	// The output of ConstructEmail has been manually put into my email client.
}
