// Package session issues, validates, expires and revokes browser sessions.
//
// A session token is a random value; the database stores only its MAC
// (keyring.SessionToken). The package provides the session contracts of
// the transports (realtime.SessionValidator, realtime.Revocations and the
// matching interfaces of internal/httpapi) with these guarantees:
//
//   - Authenticate(ctx, token) returns the principal of a valid, unexpired
//     session; every failure is fault.AuthenticationNeeded.
//   - Check(ctx, p) fails once p's session is revoked or expired, or the
//     account is locked or lost the rights recorded in p.
//   - Every revocation (Revoke, RevokeUser, RevokeAll, expiry found by
//     Authenticate, Check or Sweep) is published as one principal.Revocation
//     per session, synchronously, after the change is committed and before
//     the revoking call returns. Subscribers must not block.
//
// A session is bound to the account's auth_generation and to the
// installation's revoke-all epoch; raising either ends every session
// issued before (decision D-02: Go starts with its own sessions, the
// Python cookies are not taken over).
package session
