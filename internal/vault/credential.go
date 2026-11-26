package vault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/pyjson"
)

// ResourceKind is the kind of a resource a saved password can be assigned
// to.
type ResourceKind string

const (
	ResourceSSH   ResourceKind = "ssh"   // a saved host (profile); resource id "<id>"
	ResourceJump  ResourceKind = "jump"  // a jump host; resource id "jump:<id>"
	ResourceSOCKS ResourceKind = "socks" // a SOCKS5 proxy; resource id "socks:<id>"
	ResourceSMB   ResourceKind = "smb"   // an SMB share; resource id "smb:<id>"
)

// ResourceID returns the public resource id of the record id of a kind.
func ResourceID(kind ResourceKind, recordID string) string {
	if kind == ResourceSSH {
		return recordID
	}
	return string(kind) + ":" + recordID
}

// ParseResourceID splits a public resource id. An id without a known
// prefix is a saved host, as in the Python release.
func ParseResourceID(id string) (ResourceKind, string, error) {
	if id == "" || len(id) > maxResourceID {
		return "", "", fault.New(fault.InvalidTargets, "")
	}
	prefix, rest, found := strings.Cut(id, ":")
	if !found {
		return ResourceSSH, id, nil
	}
	switch k := ResourceKind(prefix); k {
	case ResourceJump, ResourceSOCKS, ResourceSMB:
		if rest != "" {
			return k, rest, nil
		}
	}
	return "", "", fault.New(fault.InvalidTargets, "")
}

// Limits of saved passwords (app/credential_store.py).
const (
	MaxCredentials    = 100
	MaxAssignments    = 1000
	MaxNameBytes      = 128
	MaxUsernameBytes  = 256
	MaxSecretBytes    = 4096
	maxResourceID     = 256
	IntentTTL         = 300 * time.Second
	BindingAssurance  = 300 * time.Second // a fresh step-up covers further bindings of the session
	LegacyKDF         = "scrypt-131072-8-1"
	LegacyMinPassRune = 16
	LegacyMaxPassByte = 1024
)

// Credential is a saved password without its secret. Version changes when
// the password changes; schedules bind to it (E15, E32).
type Credential struct {
	ID        string
	UserID    int64
	Name      string
	Username  string // may be empty
	Version   string
	UpdatedAt time.Time
}

// Assignment binds a credential to a resource as it was when the user
// confirmed it. Generation changes with every new or changed binding.
type Assignment struct {
	ResourceID   string
	CredentialID string
	Fingerprint  string // Fingerprint of the Target at confirmation
	Generation   string
}

// Status of the assignment of a resource, as the page shows it.
type Status string

const (
	StatusReady    Status = "ready"    // assigned and the target is unchanged
	StatusChanged  Status = "changed"  // the target changed: review and assign again
	StatusMissing  Status = "missing"  // nothing assigned
	StatusDisabled Status = "disabled" // saved passwords are turned off
)

// Target is the security-relevant part of a resource. Its Fingerprint is
// the stored binding of an assignment and the migrated value of
// credentials.json, so it is computed exactly as the Python release did
// (profile_fingerprint in app/automation_store.py). A nil field is a value
// the record does not have (JSON null).
type Target struct {
	ID           *string // public resource id
	Kind         ResourceKind
	Host         *string
	Port         *int64
	Username     *string
	AuthType     *string
	KeyID        *string
	JumpHostID   *string
	SOCKSProxyID *string
	RemoteDNS    *bool   // SOCKS only; nil means true
	Domain       *string // SMB only; nil means ""
	Share        *string // SMB only
	// RouteFingerprint is the Fingerprint of the jump host or SOCKS proxy
	// a saved host connects through (the raw jump host record without
	// prefix and kind; the typed SOCKS resource), "" without one.
	RouteFingerprint string
}

// Fingerprint returns the lower-case hex SHA-256 of the target's fields as
// sorted, compact JSON with ASCII escapes.
func Fingerprint(t Target) string {
	fields := map[string]string{
		"id": jsonString(t.ID), "host": jsonString(t.Host), "port": jsonInt(t.Port),
		"username": jsonString(t.Username), "auth_type": jsonString(t.AuthType),
		"key_id": jsonString(t.KeyID), "jump_host_id": jsonString(t.JumpHostID),
	}
	if t.SOCKSProxyID != nil && *t.SOCKSProxyID != "" {
		fields["socks_proxy_id"] = pyjson.Quote(*t.SOCKSProxyID)
	}
	switch t.Kind {
	case ResourceJump, ResourceSMB, ResourceSOCKS:
		fields["kind"] = pyjson.Quote(string(t.Kind))
	}
	if t.Kind == ResourceSOCKS {
		fields["remote_dns"] = "true"
		if t.RemoteDNS != nil && !*t.RemoteDNS {
			fields["remote_dns"] = "false"
		}
	}
	if t.Kind == ResourceSMB {
		domain := ""
		if t.Domain != nil {
			domain = *t.Domain
		}
		fields["domain"] = pyjson.Quote(domain)
		fields["share"] = jsonString(t.Share)
	}
	if t.RouteFingerprint != "" {
		fields["route_fingerprint"] = pyjson.Quote(t.RouteFingerprint)
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(pyjson.Quote(k))
		b.WriteByte(':')
		b.WriteString(fields[k])
	}
	b.WriteByte('}')
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func jsonString(s *string) string {
	if s == nil {
		return "null"
	}
	return pyjson.Quote(*s)
}

func jsonInt(n *int64) string {
	if n == nil {
		return "null"
	}
	return strconv.FormatInt(*n, 10)
}

// Resources returns the current non-secret resources of a user as
// Targets (provided in cmd/webssh by an adapter over internal/hosts and
// internal/files/smb). found is false for an id the user does not own.
type Resources interface {
	Resource(ctx context.Context, userID int64, resourceID string) (t Target, found bool, err error)
}
