// Package keyring derives per-purpose keys from SECRET_KEY and the keyring
// material and seals every secret Go writes (ADR 0008).
//
// purpose.go fixes the vocabulary shared with the capabilities: the closed
// list of purposes and the associated data that binds a ciphertext to its
// record. ring.go derives the keys (HKDF-SHA256) and seals (AES-256-GCM)
// and MACs (HMAC-SHA256) with them; material.go keeps the material file in
// the place the migration specification assigns (sections 2.2 and 5.9);
// rotate.go reseals for a new SECRET_KEY; scope.go is the browser-local
// namespace derivation of the Python release.
package keyring

import (
	"errors"
	"slices"
	"strings"
)

// Purpose selects an independent subkey. The value is part of the HKDF
// info string and therefore of every stored ciphertext and MAC: it is never
// renamed. The list is closed; a new purpose is a reviewed contract change.
type Purpose string

// Purposes of M1.
const (
	SSHKey            Purpose = "ssh_key"            // private SSH keys at rest (Seal)
	TOTP              Purpose = "totp"               // TOTP shared secrets (Seal)
	SessionToken      Purpose = "session_token"      // stored form of browser session tokens (MAC)
	CSRF              Purpose = "csrf"               // CSRF tokens bound to a session (MAC)
	StepUpGrant       Purpose = "step_up_grant"      // stored form of step-up grants (MAC)
	WebAuthnChallenge Purpose = "webauthn_challenge" // pending WebAuthn ceremonies (Seal)
	BrowserScope      Purpose = "browser_scope"      // reserved name of the browser-local namespace derivation
	FeatureApproval   Purpose = "feature_approval"   // impact approvals of security feature changes (MAC)
)

// Purposes of the M2 contracts.
const (
	Credential         Purpose = "credential"           // saved passwords at rest (Seal)
	GitHubClientSecret Purpose = "github_client_secret" // #nosec G101 -- a key purpose name; seals the GitHub client secret (Seal)
	FactorBootstrap    Purpose = "factor_bootstrap"     // stored form of one-time factor bootstrap codes (MAC)
	BackupDownload     Purpose = "backup_download"      // one-time download tokens of online backups (MAC)
)

var purposes = []Purpose{SSHKey, TOTP, SessionToken, CSRF, StepUpGrant, WebAuthnChallenge, BrowserScope, FeatureApproval,
	Credential, GitHubClientSecret, FactorBootstrap, BackupDownload}

// Purposes returns the closed list.
func Purposes() []Purpose { return slices.Clone(purposes) }

// Known reports whether p is in the closed list.
func (p Purpose) Known() bool { return slices.Contains(purposes, p) }

// AAD binds a ciphertext to the record it belongs to. A ciphertext copied
// to another table, row or column does not open.
type AAD struct {
	Table, Column, Row string
}

// ErrAAD reports associated data that cannot be encoded unambiguously.
var ErrAAD = errors.New("keyring: invalid associated data")

// Bytes encodes the associated data together with the purpose. Every part
// must be non-empty and free of NUL, so that the encoding is injective.
func (a AAD) Bytes(p Purpose) ([]byte, error) {
	if !p.Known() {
		return nil, ErrAAD
	}
	parts := []string{string(p), a.Table, a.Column, a.Row}
	for _, s := range parts {
		if s == "" || strings.IndexByte(s, 0) >= 0 {
			return nil, ErrAAD
		}
	}
	return []byte("webssh-aad-v1\x00" + strings.Join(parts, "\x00")), nil
}
