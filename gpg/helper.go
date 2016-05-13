package gpg

import (
	"io"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

// ReadEntity reads a single entity from a reader containing a list of entities.
func ReadEntity(r io.Reader, armored bool) (*openpgp.Entity, error) {
	var entity *openpgp.Entity
	var err error
	var pr *packet.Reader

	if armored {
		block, err := armor.Decode(r)
		if err != nil {
			return nil, err
		}
		r = block.Body
	}
	pr = packet.NewReader(r)

	entity, err = openpgp.ReadEntity(pr)
	if err != nil {
		return nil, err
	}

	return entity, nil
}

// DecryptPrivateKeys decrypts the private key and all private subkeys of an entity (in-place).
func DecryptPrivateKeys(entity *openpgp.Entity, passphrase []byte) error {
	err := entity.PrivateKey.Decrypt(passphrase)
	if err != nil {
		return err
	}

	for _, subkey := range entity.Subkeys {
		err = subkey.PrivateKey.Decrypt(passphrase)
		if err != nil {
			return err
		}
	}
	return nil
}

// SignClientPublicKey uses the server private key to sign the public key of the client to be validated as the given identity.
// The value of {signedIdentity} must be a valid key of {clientEntity.Identities}.
// The private keys of {serverEntity} must have been decrypted before-hand.
func SignClientPublicKey(clientEntity *openpgp.Entity, signedIdentity string, serverEntity *openpgp.Entity, w io.Writer) error {
	err := clientEntity.SignIdentity(signedIdentity, serverEntity, nil)
	if err != nil {
		return err
	}
	err = exportArmoredPublicKey(clientEntity, w)
	return err
}

// exportArmoredPublicKey exports the public key of an entity with armor as ASCII.
func exportArmoredPublicKey(entity *openpgp.Entity, w io.Writer) error {
	armoredWriter, err := armor.Encode(w, openpgp.PublicKeyType, nil)
	if err != nil {
		return err
	}
	err = entity.Serialize(armoredWriter)
	if err != nil {
		return err
	}
	err = armoredWriter.Close()
	return err
}
