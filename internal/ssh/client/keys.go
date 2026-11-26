package client

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// Key parsing errors. The texts are the ones WebSSH has shown so far. They
// are for the vault, which parses a key at upload and again for every
// connection; the dialer itself receives ready signers through KeySource.
var (
	ErrPassphraseRequired = errors.New("passphrase-encrypted private keys need a passphrase")
	ErrWrongPassphrase    = errors.New("the passphrase does not match the private key")
	ErrDSAKey             = errors.New("DSA private keys are not supported; use Ed25519, ECDSA, or RSA")
	ErrUnsupportedKey     = errors.New("unsupported or invalid private key format")
)

// KeyType is the normalized key family stored with each key.
type KeyType string

const (
	KeyRSA     KeyType = "RSA"
	KeyECDSA   KeyType = "ECDSA"
	KeyEd25519 KeyType = "Ed25519"
)

// keyAlgoDSA is only recognized to give a clear rejection.
const keyAlgoDSA = "ssh-dss"

// maxKeyBytes matches the upload limit of 64 KiB.
const maxKeyBytes = 64 << 10

// ParsePrivateKey accepts RSA, ECDSA and Ed25519 keys in OpenSSH, PEM and
// PKCS#8 encoding. passphrase may be nil for unencrypted keys.
func ParsePrivateKey(pemBytes, passphrase []byte) (ssh.Signer, KeyType, error) {
	if len(pemBytes) == 0 || len(pemBytes) > maxKeyBytes {
		return nil, "", ErrUnsupportedKey
	}
	if isDSA(pemBytes) {
		return nil, "", ErrDSAKey
	}
	var (
		raw any
		err error
	)
	if len(passphrase) > 0 {
		raw, err = ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, passphrase)
	} else {
		raw, err = ssh.ParseRawPrivateKey(pemBytes)
	}
	if err != nil {
		switch {
		case isPassphraseMissing(err):
			return nil, "", ErrPassphraseRequired
		case errors.Is(err, x509.IncorrectPasswordError):
			return nil, "", ErrWrongPassphrase
		default:
			return nil, "", fmt.Errorf("%w: %w", ErrUnsupportedKey, err)
		}
	}
	var keyType KeyType
	switch k := raw.(type) {
	case *rsa.PrivateKey:
		keyType = KeyRSA
	case *ecdsa.PrivateKey:
		keyType = KeyECDSA
	case ed25519.PrivateKey:
		keyType = KeyEd25519
	case *ed25519.PrivateKey:
		keyType, raw = KeyEd25519, *k
	default:
		return nil, "", ErrUnsupportedKey
	}
	signer, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrUnsupportedKey, err)
	}
	return signer, keyType, nil
}

// isDSA recognizes DSA keys in PEM and OpenSSH encoding, so users get a clear
// message instead of a generic format error.
func isDSA(pemBytes []byte) bool {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return false
	}
	switch block.Type {
	case "DSA PRIVATE KEY":
		return true
	case "OPENSSH PRIVATE KEY":
		return openSSHPublicKeyType(block.Bytes) == keyAlgoDSA
	}
	return false
}

// openSSHPublicKeyType reads the type of the first public key in an
// "openssh-key-v1" container without decrypting anything.
func openSSHPublicKeyType(data []byte) string {
	const magic = "openssh-key-v1\x00"
	rest, ok := bytes.CutPrefix(data, []byte(magic))
	if !ok {
		return ""
	}
	for range 3 { // cipher, kdf, kdf options
		if _, rest, ok = readString(rest); !ok {
			return ""
		}
	}
	if len(rest) < 4 || binary.BigEndian.Uint32(rest) == 0 {
		return ""
	}
	blob, _, ok := readString(rest[4:])
	if !ok {
		return ""
	}
	name, _, ok := readString(blob)
	if !ok {
		return ""
	}
	return string(name)
}

func readString(b []byte) (value, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(b)
	if int64(n) > int64(len(b)-4) {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}

func isPassphraseMissing(err error) bool {
	_, ok := errors.AsType[*ssh.PassphraseMissingError](err)
	return ok
}
