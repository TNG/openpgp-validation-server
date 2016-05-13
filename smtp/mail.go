package smtp

// MailEnvelope describes the minimum information sent and received by a mail server
type MailEnvelope struct {
	From    string
	To      []string
	Content []byte
}
