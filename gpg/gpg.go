package gpg

import (
	"io"

	"golang.org/x/crypto/openpgp"
)

// GPG contains the data necessary to perform our cryptographical actions.
type GPG struct {
	serverEntity *openpgp.Entity
}

// NewGPG initializes GPG object from buffer containing the server's private key.
func NewGPG(r io.Reader, passphrase []byte) (*GPG, error) {
	var err error

	gpg := new(GPG)
	for _, armored := range []bool{false, true} {
		gpg.serverEntity, err = ReadEntity(r, armored)
		if err == nil {
			break
		}
	}

	if err != nil {
		return nil, err
	}

	err = DecryptPrivateKeys(gpg.serverEntity, passphrase)
	if err != nil {
		return nil, err
	}

	return gpg, nil
}

// SignUserID signs an armored public key as validated to correspond to the given identity.
func (gpg *GPG) SignUserID(signedIdentity string, r io.Reader, w io.Writer) error {
	clientEntity, err := ReadEntity(r, true)
	if err != nil {
		return err
	}

	err = SignClientPublicKey(clientEntity, signedIdentity, gpg.serverEntity, w)
	return err
}
