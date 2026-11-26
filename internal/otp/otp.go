// Package otp computes one-time passwords: HOTP (RFC 4226) and TOTP
// (RFC 6238) with HMAC-SHA1, the algorithm authenticator apps use by default.
package otp

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- HOTP and TOTP are defined over HMAC-SHA1 (RFC 4226, RFC 6238)
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DefaultPeriod is the TOTP time step of RFC 6238.
const DefaultPeriod = 30 * time.Second

// MinSecretBits is the smallest secret accepted, as recommended by RFC 4226.
const MinSecretBits = 128

var errSecretTooShort = errors.New("otp: secret is shorter than 128 bits")

// DecodeSecret decodes an RFC 4648 base32 secret as authenticator apps show
// it: case-insensitive, padding optional.
func DecodeSecret(text string) ([]byte, error) {
	text = strings.ToUpper(strings.TrimRight(text, "="))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("otp: secret is not base32: %w", err)
	}
	if len(key)*8 < MinSecretBits {
		return nil, errSecretTooShort
	}
	return key, nil
}

// HOTP returns the code for counter with the given number of digits (6 to 9).
func HOTP(key []byte, counter uint64, digits int) (string, error) {
	if digits < 6 || digits > 9 {
		return "", fmt.Errorf("otp: %d digits are not supported", digits)
	}
	mac := hmac.New(sha1.New, key)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	modulus := uint32(1)
	for range digits {
		modulus *= 10
	}
	return fmt.Sprintf("%0*d", digits, value%modulus), nil
}

// Step returns the TOTP time step that contains t.
// Times before 1970 and periods under one second yield step 0.
func Step(t time.Time, period time.Duration) uint64 {
	seconds, size := t.Unix(), int64(period/time.Second)
	if seconds <= 0 || size <= 0 {
		return 0
	}
	return uint64(seconds / size) // #nosec G115 -- positive int64 fits in uint64
}

// TOTP returns the six-digit code for a time step of DefaultPeriod.
func TOTP(key []byte, step uint64) (string, error) {
	return HOTP(key, step, 6)
}
