package gpg

import (
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"io"
)

// Read a single entity from a reader containing a list of entities
func ReadEntity(r io.Reader, index int, armored bool) (*openpgp.Entity, error) {
	var entity *openpgp.Entity
	var entityList openpgp.EntityList
	var err error

	if armored {
		entityList, err = openpgp.ReadArmoredKeyRing(r)
	} else {
		entityList, err = openpgp.ReadKeyRing(r)
	}
	if err != nil {
		return nil, err
	}
    
	entity = entityList[index]

	return entity, nil
}

// Decrypt the private key and all private subkeys of an entity (in-place)
func DecryptPrivateKeys(entity *openpgp.Entity, passphrase []byte) error {
    err = entity.PrivateKey.Decrypt(passphrase)
    if err != nil {
        return err
    }
    
    for _, subkey := range entity.Subkeys {
        err = subkey.PrivateKey.Decrypt(passphrase)
        if err != nil {
            return err
        }
    }
}

// Use the server private key to sign the public key of the client to be validated as the given identity
// signedIdentity must be one of clientEntity.Identities[NAME].Name
// The private keys of serverEntity must be decrypted
func SignClientPublicKey(clientEntity *openpgp.Entity, signedIdentity string, serverEntity *openpgp.Entity, w io.Writer) error {
	err := clientEntity.SignIdentity(signedIdentity, serverEntity, nil)
	if err != nil {
		return err
	}
	err = exportArmoredPublicKey(clientEntity, w)
	return err
}

func exportArmoredPublicKey(entity *openpgp.Entity, w io.Writer) error {
	armoredWriter, err := armor.Encode(w, openpgp.PublicKeyType, nil)
	if err != nil {
		return err
	}
	err = entity.Serialize(armoredWriter)
	if err != nil {
		return err
	}
	armoredWriter.Close()
	return err
}
