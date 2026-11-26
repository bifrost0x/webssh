package ldapproto

import (
	"errors"
	"fmt"
)

// ResultCode is an LDAP resultCode (RFC 4511 section 4.1.9).
type ResultCode int

// Result codes the client distinguishes.
const (
	ResultSuccess            ResultCode = 0
	ResultTimeLimitExceeded  ResultCode = 3
	ResultSizeLimitExceeded  ResultCode = 4
	ResultReferral           ResultCode = 10
	ResultConfidentiality    ResultCode = 13
	ResultNoSuchObject       ResultCode = 32
	ResultInvalidCredentials ResultCode = 49
	ResultInsufficientAccess ResultCode = 50
	ResultUnavailable        ResultCode = 52
	ResultUnwillingToPerform ResultCode = 53
)

var (
	// ErrInvalidCredentials is returned by Bind for resultCode 49.
	ErrInvalidCredentials = errors.New("ldap: invalid credentials")
	// ErrEmptyPassword is returned before sending a bind that the server
	// would treat as unauthenticated (RFC 4513 section 5.1.2).
	ErrEmptyPassword = errors.New("ldap: refusing bind with empty password or DN")
	// ErrConnClosed is returned after the connection failed or was closed.
	ErrConnClosed = errors.New("ldap: connection closed")
	// ErrSizeLimit reports more entries than the requested size limit.
	ErrSizeLimit = errors.New("ldap: size limit exceeded")
	// ErrStartTLS reports a server that refused or broke StartTLS.
	ErrStartTLS = errors.New("ldap: starttls failed")
)

// ResultError is a non-success LDAPResult.
type ResultError struct {
	Op     string
	Result Result
}

func (e *ResultError) Error() string {
	return fmt.Sprintf("ldap: %s failed with result code %d", e.Op, e.Result.Code)
}

// ReferralError is returned when the server answers with a referral
// instead of a result. The client never follows it on its own.
type ReferralError struct {
	URLs []string
}

func (e *ReferralError) Error() string {
	return fmt.Sprintf("ldap: server returned a referral to %d location(s)", len(e.URLs))
}
