package auth

import (
	"net/http"
	"time"
)

// MsgFirstAccountHost is shown when the first account is registered or
// provisioned through a host name that may not create it.
const MsgFirstAccountHost = "The first account can only be created when WebSSH is opened by its IP address or localhost, " +
	"or by a name listed in ALLOWED_HOSTS. The administrator can also be created on the server with webssh create-admin."

// untrustedHost reports a request whose host may not register the first
// account (FirstAccountHost).
func (f *Flow) untrustedHost(r *http.Request) bool {
	return f.FirstAccountHost != nil && !f.FirstAccountHost(r)
}

// refuseFirstAccount answers a registration through an untrusted host
// while no account exists: the register page with 403 and the reason,
// and a log line, at most one a minute, that names what to do. bootstrap
// reports that the bootstrap is open, so no account exists. It returns
// false when the request may go on; a later account then needs
// accounts.CreateRequest.NotFirst to keep the check atomic.
func (f *Flow) refuseFirstAccount(w http.ResponseWriter, r *http.Request, bootstrap bool, username string) bool {
	if !f.untrustedHost(r) {
		return false
	}
	if !bootstrap {
		has, err := f.Accounts.HasAccounts(r.Context())
		if err != nil {
			f.fail(w, r, err)
			return true
		}
		if has {
			return false
		}
	}
	now := time.Now().Unix()
	if last := f.lastHostLog.Load(); now-last >= 60 && f.lastHostLog.CompareAndSwap(last, now) {
		f.logger().WarnContext(r.Context(), "first-account registration refused: the host name could be rebound to this server; "+
			"open WebSSH by its IP address or localhost, add the name to ALLOWED_HOSTS, or run `webssh create-admin`",
			"host", truncateHost(r.Host))
	}
	if username != "" && f.Audit != nil {
		f.Audit.Registration(username, false, f.clientIP(r))
	}
	f.Pages.Register(w, r, http.StatusForbidden, FormView{Flashes: []Flash{{"error", MsgFirstAccountHost}}})
	return true
}

func truncateHost(h string) string {
	if len(h) > 200 {
		return h[:200]
	}
	return h
}
