package main

import (
	"context"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files/smb"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/vault"
)

// savedPasswords adapts the vault to the connections that sign in with a
// saved password: the terminal (terminal.SavedPasswords), Quick SFTP
// through it, and SMB (smb.Passwords). A connection gets one only for the
// principal of ctx, reached over HTTPS, as connection_password required.
//
// The page names a saved password in two ways (connection_password): with
// a target token, credential_id is the password itself, authorized for
// exactly the typed target; without one, credential_id is the saved
// resource, and the connection must be that resource as it is now.
type savedPasswords struct{ vault *vault.Service }

// connecting is the principal of a connection that may use owner's saved
// passwords.
func connecting(ctx context.Context, owner int64) (principal.Principal, error) {
	p, err := principal.Require(ctx)
	switch {
	case err != nil:
		return principal.Principal{}, err
	case p.UserID != owner:
		return principal.Principal{}, fault.New(fault.AuthenticationNeeded, "")
	case !p.Secure:
		return principal.Principal{}, fault.New(fault.HTTPSRequired, "")
	}
	return p, nil
}

// Password is the password assigned to a saved host "<id>", jump host
// "jump:<id>" or SOCKS5 proxy "socks:<id>", checked against the resource
// as it is now.
func (s savedPasswords) Password(ctx context.Context, owner int64, resourceID string) (string, error) {
	if _, err := connecting(ctx, owner); err != nil {
		return "", err
	}
	t, found, err := s.vault.Resource(ctx, owner, resourceID)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fault.New(fault.CredentialMissing, "")
	}
	return s.open(ctx, owner, resourceID, t)
}

// TargetPassword is the password of a connection typed by hand: the target
// token of /api/credentials/authorize-target for exactly this host, port,
// user and route, or without a token the saved resource credentialID.
func (s savedPasswords) TargetPassword(ctx context.Context, p principal.Principal, credentialID, token string, host string, port int, user, jumpHostID, socksProxyID string) (string, error) {
	if _, err := connecting(ctx, p.UserID); err != nil {
		return "", err
	}
	port64, auth := int64(port), "password"
	t := vault.Target{Kind: vault.ResourceSSH, Host: &host, Port: &port64, Username: &user, AuthType: &auth}
	if jumpHostID != "" {
		t.JumpHostID = &jumpHostID
	}
	if socksProxyID != "" {
		t.SOCKSProxyID = &socksProxyID
	}
	if token == "" {
		return s.resource(ctx, p.UserID, credentialID, t)
	}
	secret, err := s.vault.TargetPassword(ctx, p, credentialID, token, t)
	if err != nil {
		return "", err
	}
	defer clear(secret)
	return string(secret), nil
}

// ConnectionPassword is the saved password of an SMB connection: a share
// typed by hand with its target token, or the saved share "smb:<id>".
func (s savedPasswords) ConnectionPassword(ctx context.Context, p principal.Principal, req smb.CredentialRequest) ([]byte, error) {
	if _, err := connecting(ctx, p.UserID); err != nil {
		return nil, err
	}
	f := req.Target
	port, auth := int64(445), "password"
	t := vault.Target{Kind: vault.ResourceSMB, Host: &f.Host, Port: &port, Username: &f.Username, AuthType: &auth,
		Domain: &f.Domain, Share: &f.Share}
	if req.TargetToken != "" {
		return s.vault.TargetPassword(ctx, p, req.CredentialID, req.TargetToken, t)
	}
	pw, err := s.resource(ctx, p.UserID, req.CredentialID, t)
	if err != nil {
		return nil, err
	}
	return []byte(pw), nil
}

// resource is the password of the saved resource ref when the connection
// is that resource as it is now (_connection_resource).
func (s savedPasswords) resource(ctx context.Context, owner int64, ref string, want vault.Target) (string, error) {
	if ref == "" {
		return "", fault.New(fault.InvalidRequest, "")
	}
	t, found, err := s.vault.Resource(ctx, owner, ref)
	switch {
	case err != nil:
		return "", err
	case !found:
		return "", fault.New(fault.InvalidTargets, "")
	case !sameConnection(t, want):
		return "", fault.New(fault.CredentialTargetChanged, "")
	}
	return s.open(ctx, owner, ref, t)
}

func (s savedPasswords) open(ctx context.Context, owner int64, resourceID string, t vault.Target) (string, error) {
	secret, err := s.vault.Password(ctx, owner, resourceID, t)
	if err != nil {
		return "", err
	}
	defer clear(secret)
	return string(secret), nil
}

// sameConnection compares the fields _connection_resource compares, with
// its defaults.
func sameConnection(have, want vault.Target) bool {
	str := func(p *string, def string) string {
		if p == nil {
			return def
		}
		return *p
	}
	port := func(p *int64) int64 {
		switch {
		case p != nil:
			return *p
		case want.Kind == vault.ResourceSMB:
			return 445
		case want.Kind == vault.ResourceSOCKS:
			return 1080
		}
		return 22
	}
	same := have.Kind == want.Kind && str(have.Host, "") == str(want.Host, "") && port(have.Port) == port(want.Port) &&
		str(have.Username, "") == str(want.Username, "") && str(have.AuthType, "password") == str(want.AuthType, "password") &&
		str(have.KeyID, "") == str(want.KeyID, "") && str(have.JumpHostID, "") == str(want.JumpHostID, "")
	switch want.Kind {
	case vault.ResourceSSH:
		same = same && str(have.SOCKSProxyID, "") == str(want.SOCKSProxyID, "")
	case vault.ResourceSMB:
		same = same && str(have.Domain, "") == str(want.Domain, "") && str(have.Share, "") == str(want.Share, "")
	}
	return same
}
