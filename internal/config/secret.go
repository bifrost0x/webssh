package config

import (
	"fmt"
	"io"
	"log/slog"
)

// Secret holds the application secret. It never prints its value, so a
// Config can be logged or wrapped in errors safely.
type Secret struct {
	value []byte
}

// NewSecret copies b into a Secret.
func NewSecret(b []byte) Secret { return Secret{value: append([]byte(nil), b...)} }

// Bytes returns a copy of the secret.
func (s Secret) Bytes() []byte { return append([]byte(nil), s.value...) }

// Empty reports whether no secret is set.
func (s Secret) Empty() bool { return len(s.value) == 0 }

// Format writes "[redacted]" for every verb, so no fmt verb (%d, %x on
// the bytes, ...) reveals the value.
func (s Secret) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "[redacted]") }

func (s Secret) String() string               { return "[redacted]" }
func (s Secret) GoString() string             { return "config.Secret{[redacted]}" }
func (s Secret) LogValue() slog.Value         { return slog.StringValue("[redacted]") }
func (s Secret) MarshalText() ([]byte, error) { return []byte("[redacted]"), nil }

// SecretSource says where the application secret came from. The secret
// rotation refuses to replace a secret that the environment supplies.
type SecretSource string

const (
	// SecretFromEnvironment is a SECRET_KEY value that is not a
	// placeholder.
	SecretFromEnvironment SecretSource = "environment"
	// SecretFromFile is DATA_DIR/secret_key, read or newly generated.
	SecretFromFile SecretSource = "file"
	// SecretEphemeral is a random secret for this process only, which the
	// Python release creates with DEBUG=true when no secret is set.
	// Nothing encrypted with it survives a restart.
	SecretEphemeral SecretSource = "ephemeral"
)

// secretSourceVariable is set by entrypoint.sh for the Python release.
const secretSourceVariable = "WEBSSH_SECRET_KEY_SOURCE" // #nosec G101 -- the name of a variable, not a credential
