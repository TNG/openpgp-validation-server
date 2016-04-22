package emailclient

import "testing"

func TestSendEmail(*testing.T) {
	SendMail("johannes@ebke.org", "Testmail")
}
