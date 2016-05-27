package gpg

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

// Key is a reference to an OpenPGP entity containing some public keys
type Key *openpgp.Entity

// ReadKey reads a PGP public or private key from the given reader
func ReadKey(r io.Reader) (Key, error) {
	return readEntityMaybeArmored(r)
}

// readEntity reads a single entity from a reader containing a list of entities.
func readEntity(r io.Reader, armored bool) (*openpgp.Entity, error) {
	var entity *openpgp.Entity
	var err error
	var pr *packet.Reader

	if armored {
		var block *armor.Block
		block, err = armor.Decode(r)
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

// readEntityMaybeArmored reads one entity using readEntity, first trying to interpret the reader as armored then as unarmored.
func readEntityMaybeArmored(r io.Reader) (*openpgp.Entity, error) {
	var buffer bytes.Buffer
	tee := io.TeeReader(r, &buffer)

	entity, err := readEntity(tee, true)
	if err != nil {
		entity, err = readEntity(&buffer, false)
		if err != nil {
			return nil, err
		}
	}

	return entity, nil
}

// decryptPrivateKeys decrypts the private key and all private subkeys of an entity (in-place).
func decryptPrivateKeys(entity *openpgp.Entity, passphrase []byte) error {
	if entity.PrivateKey == nil {
		return ErrNoPrivateKey
	}
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

// signClientPublicKey uses the server private key to sign the public key of the client to be validated as the given identity.
// The value of {signedIdentity} must be a valid key of {clientEntity.Identities}.
// The private keys of {serverEntity} must have been decrypted before-hand.
func signClientPublicKey(clientEntity *openpgp.Entity, signedIdentity string, serverEntity *openpgp.Entity, w io.Writer) error {
	_, ok := clientEntity.Identities[signedIdentity]
	if !ok {
		return errors.New(fmt.Sprint("Client does not have identity:", signedIdentity))
	}

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
