package gpg

import (
	"errors"
	"io"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	openpgpErrors "golang.org/x/crypto/openpgp/errors"
)

// ErrNoPrivateKey is returned when an entity does not contain needed private keys.
var ErrNoPrivateKey = errors.New("gpg: Entity contains no private key to decrypt")

// ErrMessageNotSigned is returned when to be decrypted message was not signed by anybody.
var ErrMessageNotSigned = errors.New("gpg: Message not signed")

// ErrMessageNotEncrypted is returned when to be decrypted message is not encrypted.
var ErrMessageNotEncrypted = errors.New("gpg: Message not encrypted")

// ErrUnknownIdentity is returned when an identity could not be found within the identities of a key.
var ErrUnknownIdentity = errors.New("gpg: Identity not associated with client key")

// ErrUnknownIssuer is returned when the issuer of a signature is not known.
var ErrUnknownIssuer = openpgpErrors.ErrUnknownIssuer

// GPG contains the data necessary to perform our cryptographical actions.
type GPG struct {
	serverEntity *openpgp.Entity
}

// NewGPG initializes a GPG object from a buffer containing the server's private key.
func NewGPG(r io.Reader, passphrase string) (*GPG, error) {
	var err error

	gpg := new(GPG)
	gpg.serverEntity, err = readEntityMaybeArmored(r)
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
		return ErrUnknownIdentity
	}

	err = signClientPublicKey(clientEntity, signedIdentity, gpg.serverEntity, w)
	return err
}

// SignMessage signs message and writes the armored detached signature to w.
func (gpg *GPG) SignMessage(message io.Reader, w io.Writer) error {
	return openpgp.ArmoredDetachSign(w, gpg.serverEntity, message, nil)
}

// CheckMessageSignature checks whether an armored detached signature is valid for a given message and has been made by the given signer.
func (gpg *GPG) CheckMessageSignature(message io.Reader, signature io.Reader, checkedSignerKey io.Reader) error {
	checkedSignerEntity, err := readEntityMaybeArmored(checkedSignerKey)
	keyRing := openpgp.EntityList([]*openpgp.Entity{checkedSignerEntity})

	_, err = openpgp.CheckArmoredDetachedSignature(keyRing, message, signature)

	return err
}

type encodeEncryptStream struct {
	encryptStream, armorStream io.WriteCloser
}

func (s *encodeEncryptStream) Write(p []byte) (n int, err error) {
	return s.encryptStream.Write(p)
}

func (s *encodeEncryptStream) Close() error {
	err := s.encryptStream.Close()
	if err != nil {
		return err
	}
	return s.armorStream.Close()
}

// EncryptMessage encrypts a message using the server's entity for the given recipient and writes the cipher text to output.
func (gpg *GPG) EncryptMessage(output io.Writer, recipientKey io.Reader) (plaintext io.WriteCloser, err error) {
	recipient, err := readEntityMaybeArmored(recipientKey)
	if err != nil {
		return nil, err
	}
	armorStream, err := armor.Encode(output, "PGP MESSAGE", map[string]string{"Version": "GnuPG v2"})
	if err != nil {
		return nil, err
	}
	encryptStream, err := openpgp.Encrypt(armorStream, []*openpgp.Entity{recipient}, gpg.serverEntity, nil, nil)
	if err != nil {
		return nil, err
	}
	return &encodeEncryptStream{encryptStream, armorStream}, nil
}

// DecryptSignedMessage decrypts an encrypted message sent to server, checks the (mandatory) embedded signature made by the given sender and write the plain text to output.
func (gpg *GPG) DecryptSignedMessage(message io.Reader, output io.Writer, senderPublicKey io.Reader) error {
	senderEntity, err := readEntityMaybeArmored(senderPublicKey)
	if err != nil {
		return err
	}
	keyRing := openpgp.EntityList([]*openpgp.Entity{gpg.serverEntity, senderEntity})

	md, err := openpgp.ReadMessage(message, keyRing, nil, nil)
	if err != nil {
		return err
	}
	if !md.IsEncrypted {
		return ErrMessageNotEncrypted
	}
	if !md.IsSigned {
		return ErrMessageNotSigned
	}
	if md.SignedByKeyId != senderEntity.PrimaryKey.KeyId {
		return openpgpErrors.ErrUnknownIssuer
	}

	_, err = io.Copy(output, md.UnverifiedBody)
	if err != nil {
		return err
	}

	// SignatureError can only be checked after reading all of UnverifiedBody
	if md.SignatureError != nil {
		// TODO Find a way to test this branch?
		return md.SignatureError
	}

	return nil
}
