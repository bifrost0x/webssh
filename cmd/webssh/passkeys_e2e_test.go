//go:build e2e

package main

import (
	"bytes"
	"testing"

	"github.com/bifrost0x/webssh/internal/auth/webauthn"
)

// The seed's passkey placeholder is a valid COSE key, so the store takes
// it, and a fresh one each time, so no two accounts share a key.
func TestPasskeyPlaceholderKey(t *testing.T) {
	a, err := unusablePasskeyKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := webauthn.ParseCOSEKey(a); err != nil {
		t.Fatalf("placeholder key: %v", err)
	}
	b, err := unusablePasskeyKey()
	if err != nil || bytes.Equal(a, b) {
		t.Fatalf("placeholder keys repeat: %v", err)
	}
}
