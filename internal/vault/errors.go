package vault

import (
	"errors"
	"fmt"

	"github.com/bifrost0x/webssh/internal/fault"
)

// DetailPassphraseRequired is the err.details member that asks the page to
// request the key's passphrase and send the request again with it. It is
// set for a missing and for a wrong passphrase.
const DetailPassphraseRequired = "passphrase_required"

var errNotFound = errors.New("vault: key not found")

// Texts shown to the user. Those of the Python release are kept verbatim
// because the page and the end-to-end specs show them.
const (
	textNameContentRequired = "Name and key content required"
	textIDContentRequired   = "Key ID and key content required"
	textIDRequired          = "Key ID required"
	textInvalidName         = "Invalid key name"
	textNameTooLong         = "Key name too long (max 128 characters)"
	textContentTooLarge     = "Key content too large (max 64KB)"
	textInvalidKey          = "Unsupported or invalid private key format"
	textDSA                 = "DSA private keys are not supported; use Ed25519, ECDSA, or RSA"
	textNotFound            = "Key not found"
	textStorageLimit        = "SSH key storage limit reached; delete a key or replace one with a smaller key"
	textPassphraseMissing   = "This private key is protected by a passphrase. Enter the passphrase to upload it."
	textPassphraseWrong     = "The passphrase does not match the private key."
	textPassphraseTooLong   = "The passphrase is too long."
	textEncryptedPKCS8      = "Encrypted PKCS#8 private keys are not supported. Convert the key to the OpenSSH format with ssh-keygen -p, or remove its passphrase."
	textKDFRounds           = "The passphrase protection of this key uses more than 256 bcrypt rounds. Change the passphrase with ssh-keygen -p -a 100 and upload it again."
	textUnusable            = "The SSH key cannot be used. Replace it with an RSA, ECDSA or Ed25519 key."
	textBusy                = "Other keys are being checked. Try again in a moment."
)

func invalid(text string) error { return fault.New(fault.InvalidValue, text) }

// keyFault maps a parse failure to the error the user sees.
func keyFault(err error) error {
	var e *fault.Error
	switch {
	case errors.Is(err, errPassphraseMissing):
		e = fault.New(fault.InvalidValue, textPassphraseMissing)
		e.Details = map[string]any{DetailPassphraseRequired: true}
	case errors.Is(err, errPassphraseWrong):
		e = fault.New(fault.InvalidValue, textPassphraseWrong)
		e.Details = map[string]any{DetailPassphraseRequired: true}
	case errors.Is(err, errKeyDSA):
		e = fault.New(fault.InvalidValue, textDSA)
	case errors.Is(err, errEncryptedPKCS8):
		e = fault.New(fault.InvalidValue, textEncryptedPKCS8)
	case errors.Is(err, errKDFRounds):
		e = fault.New(fault.InvalidValue, textKDFRounds)
	default:
		e = fault.New(fault.InvalidValue, textInvalidKey)
	}
	return e
}

func notFound() error { return fault.New(fault.NotFound, textNotFound) }

func storageLimit() error { return fault.New(fault.Conflict, textStorageLimit) }

func typeMismatch(stored string) error {
	switch stored {
	case KeyRSA, KeyECDSA, KeyEd25519:
	default:
		// A migrated key's type is whatever its metadata said; it is not
		// echoed.
		return fault.New(fault.InvalidValue, "Replacement key must use the same key type")
	}
	return fault.New(fault.InvalidValue, fmt.Sprintf("Replacement key must use the same key type (%s)", stored))
}

// storage wraps a database or keyring failure; the cause is logged by the
// transport, never sent.
func storage(err error) error {
	if _, ok := fault.From(err); ok {
		return err
	}
	if errors.Is(err, errNotFound) {
		return notFound()
	}
	return fault.Wrap(fault.StorageError, err, "")
}
