package vault

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"golang.org/x/crypto/ssh"
)

// Key types as stored and shown (the names of the Python release).
const (
	KeyRSA     = "RSA"
	KeyECDSA   = "ECDSA"
	KeyEd25519 = "Ed25519"
)

// Upload limits. MaxKeyBytes is the Python limit on the key text in UTF-8
// bytes, MaxNameRunes the limit on the name in characters.
const (
	MaxKeyBytes        = 64 << 10
	MaxNameRunes       = 128
	MaxPassphraseBytes = 1024
	minRSABits         = 1024
)

// maxKDFRounds bounds the bcrypt rounds of a passphrase-protected OpenSSH
// key. The rounds come from the uploaded file; without a bound one upload
// could keep a CPU busy for hours. ssh-keygen uses 16 unless told
// otherwise; a round costs about 7 ms (measured for an Ed25519 key with
// aes256-ctr), so the bound keeps one upload under one second and still
// loads keys made with -a 100.
const maxKDFRounds = 128

// Reasons a key is refused. They are matched with errors.Is and mapped to
// user texts in errors.go.
var (
	errKeyInvalid        = errors.New("vault: unsupported or invalid private key")
	errKeyDSA            = errors.New("vault: DSA private key")
	errPassphraseMissing = errors.New("vault: passphrase required")
	errPassphraseWrong   = errors.New("vault: wrong passphrase")
	errEncryptedPKCS8    = errors.New("vault: encrypted PKCS#8 private key")
	errKDFRounds         = errors.New("vault: too many KDF rounds")
)

// parsedKey is a private key that WebSSH can use.
type parsedKey struct {
	signer  ssh.Signer
	keyType string
	// stored is the unencrypted private key as it is sealed: the uploaded
	// text when it had no passphrase, else the key in OpenSSH form.
	stored []byte
}

// parseKey reads an uploaded private key. passphrase is used only when the
// key is protected; it is never stored.
func parseKey(content, passphrase []byte) (parsedKey, error) {
	if len(content) == 0 || len(content) > MaxKeyBytes {
		return parsedKey{}, errKeyInvalid
	}
	block, _ := pem.Decode(content)
	if block == nil {
		return parsedKey{}, errKeyInvalid
	}
	switch block.Type {
	case "DSA PRIVATE KEY":
		return parsedKey{}, errKeyDSA
	case "ENCRYPTED PRIVATE KEY":
		return parsedKey{}, errEncryptedPKCS8
	case "OPENSSH PRIVATE KEY":
		// A container whose header does not read is refused before the
		// library runs its KDF with options nobody checked.
		info, ok := inspectOpenSSH(block.Bytes)
		switch {
		case !ok:
			return parsedKey{}, errKeyInvalid
		case info.keyType == "ssh-dss":
			return parsedKey{}, errKeyDSA
		case info.rounds > maxKDFRounds:
			return parsedKey{}, errKDFRounds
		}
	}

	raw, err := ssh.ParseRawPrivateKey(content)
	stored := content
	if _, missing := errors.AsType[*ssh.PassphraseMissingError](err); missing {
		if len(passphrase) == 0 {
			return parsedKey{}, errPassphraseMissing
		}
		raw, err = ssh.ParseRawPrivateKeyWithPassphrase(content, passphrase)
		if errors.Is(err, x509.IncorrectPasswordError) {
			return parsedKey{}, errPassphraseWrong
		}
		stored = nil
	}
	if err != nil {
		return parsedKey{}, errKeyInvalid
	}
	key, keyType, ok := normalize(raw)
	if !ok {
		return parsedKey{}, errKeyInvalid
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return parsedKey{}, errKeyInvalid
	}
	if stored == nil {
		b, err := ssh.MarshalPrivateKey(key, "")
		if err != nil {
			return parsedKey{}, errKeyInvalid
		}
		stored = pem.EncodeToMemory(b)
	}
	return parsedKey{signer: signer, keyType: keyType, stored: stored}, nil
}

// normalize accepts the key families WebSSH supports.
func normalize(raw any) (crypto.Signer, string, bool) {
	switch k := raw.(type) {
	case *rsa.PrivateKey:
		// crypto/rsa refuses to sign with shorter keys; such a key would be
		// listed as usable and fail at every connection.
		return k, KeyRSA, k.N.BitLen() >= minRSABits
	case *ecdsa.PrivateKey:
		return k, KeyECDSA, true
	case ed25519.PrivateKey:
		return k, KeyEd25519, true
	case *ed25519.PrivateKey:
		return *k, KeyEd25519, true
	}
	return nil, "", false
}

// signerOf parses a stored key for a connection. Stored keys never carry a
// passphrase.
func signerOf(stored []byte) (ssh.Signer, string, error) {
	raw, err := ssh.ParseRawPrivateKey(stored)
	if err != nil {
		return nil, "", errKeyInvalid
	}
	key, keyType, ok := normalize(raw)
	if !ok {
		return nil, "", errKeyInvalid
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, "", errKeyInvalid
	}
	return signer, keyType, nil
}
