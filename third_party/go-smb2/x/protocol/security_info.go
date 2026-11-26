package protocol

import (
	"errors"

	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

// ErrEncryptionUnavailable reports that RequireEncryption was set but the
// connection negotiated no cipher or the session cannot derive keys.
var ErrEncryptionUnavailable = errors.New("protocol: encryption required but unavailable")

// ErrCredentialsRequired reports that RequireEncryption was set for an
// anonymous initiator. An anonymous session derives no keys, so Dial refuses
// it before sending anything.
var ErrCredentialsRequired = errors.New("protocol: encryption required but the initiator has no credentials")

// SecurityInfo describes the negotiated security of an established session.
type SecurityInfo struct {
	Dialect          Dialect
	Cipher           Cipher
	SigningAlgorithm wire.SigningAlgorithm
	SigningRequired  bool
	EncryptData      bool
	Guest            bool
	Null             bool
}

// SecurityInfo returns the negotiated dialect, cipher and session flags.
func (c *Session) SecurityInfo() SecurityInfo {
	if c == nil || c.s == nil {
		return SecurityInfo{}
	}
	s := c.s
	return SecurityInfo{
		Dialect:          Dialect(s.dialect),
		Cipher:           Cipher(s.cipherId),
		SigningAlgorithm: s.signingAlgorithm,
		SigningRequired:  s.requireSigning,
		EncryptData:      s.sessionFlags&wire.SMB2_SESSION_FLAG_ENCRYPT_DATA != 0,
		Guest:            s.sessionFlags&wire.SMB2_SESSION_FLAG_IS_GUEST != 0,
		Null:             s.sessionFlags&wire.SMB2_SESSION_FLAG_IS_NULL != 0 || s.anonymous,
	}
}

// ShareFlags returns the SMB2 TREE_CONNECT ShareFlags.
func (tc *Tree) ShareFlags() uint32 {
	if tc == nil {
		return 0
	}
	return tc.shareFlags
}

// IsDFS reports whether the server marked the tree as a DFS share.
func (tc *Tree) IsDFS() bool {
	return tc != nil && (tc.isDFSShare || tc.shareFlags&(wire.SMB2_SHAREFLAG_DFS|wire.SMB2_SHAREFLAG_DFS_ROOT) != 0)
}

// Encrypted reports whether requests on this tree are encrypted.
func (tc *Tree) Encrypted() bool {
	return tc != nil && (tc.session.sessionFlags&wire.SMB2_SESSION_FLAG_ENCRYPT_DATA != 0 || tc.shareFlags&wire.SMB2_SHAREFLAG_ENCRYPT_DATA != 0)
}
