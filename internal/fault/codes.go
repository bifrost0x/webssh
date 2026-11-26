package fault

// Code is a stable, machine-readable failure class. Codes are part of the
// external contract: the browser, the realtime shim and the end-to-end
// specs match on them, so a code is never renamed or reused for another
// meaning. New codes are added to the catalog below and to
// docs/architecture/m1-contracts.md; the architecture tests keep both in
// step.
type Code string

// Request and access failures.
const (
	InvalidRequest        Code = "invalid_request"         // malformed or incomplete request
	InvalidValue          Code = "invalid_value"           // a field is out of its allowed set or range
	TooLarge              Code = "too_large"               // body, payload or field exceeds its limit
	AuthenticationNeeded  Code = "authentication_required" // no valid browser session
	Forbidden             Code = "forbidden"               // authenticated, but not allowed
	CSRFExpired           Code = "csrf_expired"            // CSRF token missing, wrong or from another session
	StepUpRequired        Code = "step_up_required"        // the action needs a fresh step-up grant
	StepUpFailed          Code = "step_up_failed"          // the step-up proof was wrong
	MFARestart            Code = "mfa_restart"             // the pending sign-in expired; start again
	LastFactorRequired    Code = "last_factor_required"    // removing this factor would leave none
	NotFound              Code = "not_found"               // the resource does not exist for this principal
	Conflict              Code = "conflict"                // the change conflicts with current state
	PreconditionFailed    Code = "precondition_failed"     // If-Match or a confirmed impact no longer holds
	RateLimited           Code = "rate_limited"            // too many attempts; see RetryAfter
	Busy                  Code = "busy"                    // a concurrent operation holds the resource
	NotAvailableInPreview Code = "not_available_in_preview"
	Maintenance           Code = "maintenance" // the server is in maintenance mode
	Unavailable           Code = "unavailable" // a dependency is down or the server is stopping
	StorageError          Code = "storage_error"
	Internal              Code = "internal"
)

// Codes the overview preferences of the Python release send; the page
// keeps matching on them.
const (
	InvalidLayout    Code = "invalid_layout"    // the overview panel arrangement is invalid
	InvalidDismissed Code = "invalid_dismissed" // the acknowledged attention items are invalid
	StorageFailed    Code = "storage"           // the overview preferences could not be saved
)

// Realtime transport failures (internal/realtime, internal/realtime/protocol).
const (
	UnknownType        Code = "unknown_type"        // no handler for the message type
	VersionUnsupported Code = "version_unsupported" // no common schema version
	Backpressure       Code = "backpressure"        // the client did not keep up
	InputTooLarge      Code = "ssh_input_too_large"
	InputBackpressure  Code = "ssh_input_backpressure"
	ChannelInUse       Code = "channel_in_use" // the client reused a channel number
)

// SSH connection failures (internal/ssh/client, internal/ssh/hostkey,
// internal/netpolicy). They describe what failed, never remote-supplied
// text.
const (
	Unreachable         Code = "unreachable"
	Timeout             Code = "timeout"
	Cancelled           Code = "connection_cancelled"
	TargetBlocked       Code = "target_blocked" // refused by the outbound network policy
	HostKeyChanged      Code = "host_key_changed"
	HostKeyNotAccepted  Code = "host_key_not_accepted"
	HostKeyRevoked      Code = "host_key_revoked"
	NoCommonAlgorithm   Code = "no_common_algorithm"
	AuthFailed          Code = "auth_failed"
	InteractionRequired Code = "interaction_required"
	BannerDeclined      Code = "auth_banner_declined"
	SSHProtocol         Code = "ssh_protocol_error"
	ChannelRejected     Code = "channel_rejected"

	// The tailnet rule of the network policy refused the target or relay;
	// the page shows its own hint (admins get a link to the setting).
	TailnetRouteRestricted Code = "tailscale_route_restricted"
)

// SOCKS5 failures (internal/ssh/client). The spelling is that of the
// Python release (app/socks5_client.py); static/js/ssh-error-ui.js shows
// a text and a link to the proxy settings for each.
const (
	SOCKSProxyFailure       Code = "socks_proxy_failure"
	SOCKSNotAllowed         Code = "socks_not_allowed"
	SOCKSNetworkUnreachable Code = "socks_network_unreachable"
	SOCKSHostUnreachable    Code = "socks_host_unreachable"
	SOCKSConnectionRefused  Code = "socks_connection_refused"
	SOCKSTTLExpired         Code = "socks_ttl_expired"
	SOCKSUnsupported        Code = "socks_unsupported"
	SOCKSProtocolError      Code = "socks_protocol_error"
	SOCKSProxyUnreachable   Code = "socks_proxy_unreachable"
	SOCKSTimeout            Code = "socks_timeout"
	SOCKSAuthRequired       Code = "socks_auth_required"
)

// HTTP status codes used by the catalog. They are spelled out here so that
// this foundation package does not import net/http (ADR 0003).
const (
	statusBadRequest          = 400
	statusUnauthorized        = 401
	statusForbidden           = 403
	statusNotFound            = 404
	statusConflict            = 409
	statusPreconditionFailed  = 412
	statusContentTooLarge     = 413
	statusTooManyRequests     = 429
	statusInternalServerError = 500
	statusNotImplemented      = 501
	statusBadGateway          = 502
	statusServiceUnavailable  = 503
	statusGatewayTimeout      = 504
)

// entry is the fixed presentation of one code.
type entry struct {
	status  int
	message string // default text, safe to show
}

var catalog = map[Code]entry{
	InvalidRequest:        {statusBadRequest, "The request is invalid."},
	InvalidValue:          {statusBadRequest, "A value is not allowed."},
	TooLarge:              {statusContentTooLarge, "The request is too large."},
	AuthenticationNeeded:  {statusUnauthorized, "Sign in to continue."},
	Forbidden:             {statusForbidden, "You are not allowed to do this."},
	CSRFExpired:           {statusBadRequest, "The page has expired. Reload it and try again."},
	StepUpRequired:        {statusForbidden, "Confirm your identity to continue."},
	StepUpFailed:          {statusForbidden, "The confirmation failed."},
	MFARestart:            {statusBadRequest, "The sign-in has expired. Start again."},
	LastFactorRequired:    {statusConflict, "At least one second factor must remain."},
	NotFound:              {statusNotFound, "Not found."},
	Conflict:              {statusConflict, "The change conflicts with the current state."},
	PreconditionFailed:    {statusPreconditionFailed, "The data has changed. Reload and try again."},
	RateLimited:           {statusTooManyRequests, "Too many attempts. Try again later."},
	Busy:                  {statusConflict, "Another operation is in progress."},
	NotAvailableInPreview: {statusNotImplemented, "Not available in this preview yet."},
	Maintenance:           {statusServiceUnavailable, "The server is in maintenance mode."},
	Unavailable:           {statusServiceUnavailable, "The service is unavailable."},
	StorageError:          {statusInternalServerError, "The data could not be stored."},
	Internal:              {statusInternalServerError, "An internal error occurred."},
	InvalidLayout:         {statusBadRequest, "The overview layout is invalid."},
	InvalidDismissed:      {statusBadRequest, "The acknowledgement list is invalid."},
	StorageFailed:         {statusInternalServerError, "The overview settings could not be saved."},

	UnknownType:        {statusBadRequest, "Unknown message type."},
	VersionUnsupported: {statusBadRequest, "Reload the page to use the current version."},
	Backpressure:       {statusServiceUnavailable, "The connection did not keep up."},
	InputTooLarge:      {statusContentTooLarge, "The input is too large."},
	InputBackpressure:  {statusServiceUnavailable, "The terminal is not accepting input right now."},
	ChannelInUse:       {statusConflict, "The terminal channel is already in use."},

	Unreachable:         {statusBadGateway, "The host could not be reached."},
	Timeout:             {statusGatewayTimeout, "The connection timed out."},
	Cancelled:           {statusBadRequest, "The connection was cancelled."},
	TargetBlocked:       {statusForbidden, "The network policy does not allow this target."},
	HostKeyChanged:      {statusBadGateway, "The host key has changed."},
	HostKeyNotAccepted:  {statusBadGateway, "The host key was not accepted."},
	HostKeyRevoked:      {statusBadGateway, "The host key is revoked."},
	NoCommonAlgorithm:   {statusBadGateway, "No common SSH algorithm."},
	AuthFailed:          {statusBadGateway, "Authentication failed."},
	InteractionRequired: {statusBadGateway, "The host asks for input that cannot be answered here."},
	BannerDeclined:      {statusBadRequest, "The login banner was declined."},
	SSHProtocol:         {statusBadGateway, "The SSH connection failed."},
	ChannelRejected:     {statusBadGateway, "The host refused the session."},

	TailnetRouteRestricted: {statusForbidden, "This target is on the tailnet and requires Tailscale SSH."},

	// The statuses are those of the general codes the failures had
	// before they got their own (unreachable, timeout, target_blocked,
	// auth_failed, ssh_protocol_error).
	SOCKSProxyFailure:       {statusBadGateway, "The SOCKS5 proxy reported a general failure."},
	SOCKSNotAllowed:         {statusForbidden, "The SOCKS5 proxy does not allow this connection."},
	SOCKSNetworkUnreachable: {statusBadGateway, "The SOCKS5 proxy cannot reach the target network."},
	SOCKSHostUnreachable:    {statusBadGateway, "The SOCKS5 proxy cannot reach the target host."},
	SOCKSConnectionRefused:  {statusBadGateway, "The target refused the connection through the SOCKS5 proxy."},
	SOCKSTTLExpired:         {statusGatewayTimeout, "The connection through the SOCKS5 proxy timed out."},
	SOCKSUnsupported:        {statusBadGateway, "The SOCKS5 proxy does not support this request."},
	SOCKSProtocolError:      {statusBadGateway, "The SOCKS5 proxy sent an invalid response."},
	SOCKSProxyUnreachable:   {statusBadGateway, "The SOCKS5 proxy could not be reached."},
	SOCKSTimeout:            {statusGatewayTimeout, "The SOCKS5 proxy did not respond in time."},
	SOCKSAuthRequired:       {statusBadGateway, "The SOCKS5 proxy requires a username and password."},
}

// Codes returns every code of the catalog, for tests and documentation.
func Codes() []Code {
	codes := make([]Code, 0, len(catalog))
	for c := range catalog {
		codes = append(codes, c)
	}
	return codes
}

// Known reports whether c is in the catalog.
func (c Code) Known() bool {
	_, ok := catalog[c]
	return ok
}

// HTTPStatus returns the HTTP status for c; unknown codes map to 500.
func (c Code) HTTPStatus() int {
	if e, ok := catalog[c]; ok {
		return e.status
	}
	return statusInternalServerError
}

// DefaultMessage returns the safe default text for c.
func (c Code) DefaultMessage() string {
	if e, ok := catalog[c]; ok {
		return e.message
	}
	return catalog[Internal].message
}
