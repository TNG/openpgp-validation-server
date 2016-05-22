package gpg

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/openpgp"
)

// GPG contains the data necessary to perform our cryptographical actions.
type GPG struct {
	serverEntity *openpgp.Entity
}

// NewGPG initializes a GPG object from a buffer containing the server's private key.
func NewGPG(r io.Reader, passphrase string) (*GPG, error) {
	var err error
	var buffer bytes.Buffer
	tee := io.TeeReader(r, &buffer)

	gpg := new(GPG)
	gpg.serverEntity, err = readEntity(tee, true)
	if err != nil {
		gpg.serverEntity, err = readEntity(&buffer, false)
		if err != nil {
			return nil, err
		}
	}

	if err != nil {
		return nil, err
	}

	err = decryptPrivateKeys(gpg.serverEntity, []byte(passphrase))
	if err != nil {
		return nil, err
	}

	return gpg, nil
}

// SignUserID signs an armored public key read from r as validated to correspond to the given email and writes the signed public key to w.
func (gpg *GPG) SignUserID(signedEMail string, r io.Reader, w io.Writer) error {
	clientEntity, err := readEntity(r, true)
	if err != nil {
		return err
	}
	signedIdentity := ""
	for _, identity := range clientEntity.Identities {
		if identity.UserId.Email == signedEMail {
			signedIdentity = identity.Name
			break
		}
	}

	if signedIdentity == "" {
		return errors.New(fmt.Sprint("Could not find", signedEMail, "in identities of client key"))
	}

	err = signClientPublicKey(clientEntity, signedIdentity, gpg.serverEntity, w)
	return err
}

// SignMessage signs message and writes the armored signature to w.
func (gpg *GPG) SignMessage(message io.Reader, w io.Writer) error {
	return openpgp.ArmoredDetachSign(w, gpg.serverEntity, message, nil)
}
