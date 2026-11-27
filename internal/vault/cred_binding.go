package vault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
)

// Binding is the state of the saved password of a resource for the
// target t a caller is about to use (credential_status), and, when it is
// ready, a token of the binding (generations): it changes with every new
// or changed assignment, a replaced password and every change of the
// saved-password switch. A run and a schedule keep the token of their
// review and stop when it changes. The token reveals nothing about the
// secret.
func (s *Service) Binding(ctx context.Context, userID int64, resourceID string, t Target) (Status, string, error) {
	c, err := s.credentials()
	if err != nil {
		return "", "", err
	}
	enabled, revision, err := c.policy(ctx, true)
	if err != nil {
		return "", "", err
	}
	if !enabled {
		return StatusDisabled, "", nil
	}
	all, _, err := c.resources(ctx, userID)
	if err != nil {
		return "", "", err
	}
	current, err := resolve(all, resourceID)
	if err != nil {
		return StatusMissing, "", nil //nolint:nilerr // an unknown or ambiguous resource has no binding
	}
	d, err := s.readDoc(ctx, userID)
	if err != nil {
		return "", "", err
	}
	a, ok := d.assignment(resourceID)
	if !ok {
		return StatusMissing, "", nil
	}
	rec, ok := d.record(a.CredentialID)
	if !ok {
		return StatusMissing, "", nil
	}
	want := Fingerprint(t)
	if !current.Password || current.Fingerprint == "" || current.Fingerprint != want || a.Fingerprint != want {
		return StatusChanged, "", nil
	}
	sum := sha256.Sum256([]byte(revision + "\x00" + a.Generation + "\x00" + rec.ID + "\x00" + rec.Version))
	return StatusReady, hex.EncodeToString(sum[:]), nil
}
