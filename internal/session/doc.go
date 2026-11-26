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
//   - Every revocation (Revoke, RevokeUser, expiry found by Check) is
//     published as one principal.Revocation per session, synchronously,
//     after the change is committed and before the revoking call returns.
//     Subscribers must not block.
package session
