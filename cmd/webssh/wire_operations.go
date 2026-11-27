package main

import (
	"context"
	"time"

	"github.com/bifrost0x/webssh/internal/audit"
	"github.com/bifrost0x/webssh/internal/auth/stepup"
	"github.com/bifrost0x/webssh/internal/buildinfo"
	"github.com/bifrost0x/webssh/internal/httpapi"
	"github.com/bifrost0x/webssh/internal/jobs"
	"github.com/bifrost0x/webssh/internal/operations"
	"github.com/bifrost0x/webssh/internal/quota"
	"github.com/bifrost0x/webssh/internal/realtime"
	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/terminal"
)

// operationsArea wires the area "operations" (OP3): audit, instance operations and the support report (internal/audit, internal/operations, internal/settings).
// OP3 fills in the hooks; no other package edits this file.
func operationsArea() extension {
	return extension{name: "operations", wire: wireOperations}
}

// The providers satisfy the consumer interfaces of the area.
var (
	_ settings.StepUp        = (*stepup.Service)(nil)
	_ settings.Auditor       = (*audit.Logger)(nil)
	_ operations.StepUp      = (*stepup.Service)(nil)
	_ operations.Auditor     = (*audit.Logger)(nil)
	_ operations.Sockets     = realtimeOps{}
	_ operations.Connections = realtimeOps{}
	_ operations.Sessions    = terminalOps{}
	_ operations.Jobs        = jobsOps{}
	_ operations.Quotas      = quotaOps{}
	_ operations.Usernames   = accountNames{}
)

func wireOperations(sys *system) error {
	mux := sys.edge.Mux()
	adminPanel := sys.cfg.Accounts.AdminPanelEnabled
	(&settings.AdminHTTP{Settings: sys.settings, StepUp: sys.stepup, Audit: sys.audit, Enabled: adminPanel,
		TailscaleSSHEnabled: sys.cfg.Network.TailscaleSSHEnabled, Changed: settingsChanged(sys), Logger: sys.log}).Register(mux)
	in := &operations.Instance{
		Connections: realtimeOps{sys.realtime}, Sockets: realtimeOps{sys.realtime},
		Sessions: terminalOps{sys.terminal}, Jobs: jobsOps{sys.jobs}, Quotas: quotaOps{sys.quotas},
		Names: accountNames{sys}, Maintenance: sys.maintenance.Load,
	}
	(&operations.InstanceHTTP{Instance: in, StepUp: sys.stepup, Audit: sys.audit, Enabled: adminPanel, Logger: sys.log}).Register(mux)
	(&audit.HTTP{Logger: sys.audit, Retention: sys.settings, StepUp: sys.stepup, Enabled: sys.cfg.Audit.ExportEnabled,
		Log: sys.log}).Register(mux)
	(&operations.SupportHTTP{Facts: supportFacts{sys}, HTTPS: httpapi.ReachedOverHTTPS}).Register(mux)
	return nil
}

// settingsChanged applies the effects of an administrator change outside
// the store: switching the SSH gateway off cancels its pending attempts.
func settingsChanged(sys *system) func(context.Context, map[string]settings.AdminChange) {
	return func(_ context.Context, changes map[string]settings.AdminChange) {
		if c, ok := changes["ssh_gateway_enabled"]; ok && c.Current == false {
			if v, ok := sys.optional.terminalVariants.(*variantProvider); ok {
				v.registry.Disable()
			}
		}
	}
}

// realtimeOps adapts the realtime endpoint to the instance view.
type realtimeOps struct{ s *realtime.Server }

func (r realtimeOps) Live() []operations.LiveConnection {
	if r.s == nil {
		return nil
	}
	open := r.s.OpenConnections()
	out := make([]operations.LiveConnection, 0, len(open))
	for _, c := range open {
		out = append(out, operations.LiveConnection{ID: c.ID, UserID: c.UserID, CreatedAt: c.Opened})
	}
	return out
}

func (r realtimeOps) Disconnect(_ context.Context, id string) (bool, error) {
	return r.s.DisconnectConnection(id), nil
}

func (r realtimeOps) SocketStats() operations.SocketStats {
	if r.s == nil {
		return operations.SocketStats{}
	}
	c := r.s.Capacity()
	return operations.SocketStats{Active: c.Open, Limit: c.Max, PerUserLimit: c.MaxPerUser,
		RejectedTotal: c.RefusedServer, RejectedPerUser: c.RefusedPerUser}
}

// terminalOps adapts the terminal manager to the instance view.
type terminalOps struct{ m *terminal.Manager }

func (t terminalOps) Live() (int, []operations.LiveSession) {
	if t.m == nil {
		return 0, nil
	}
	all := t.m.AdminSessions()
	out := make([]operations.LiveSession, 0, len(all))
	for _, s := range all {
		out = append(out, operations.LiveSession{ID: s.ID, UserID: s.Owner, Target: s.Target, Tmux: s.Tmux, CreatedAt: s.Created})
	}
	return len(out), out
}

func (t terminalOps) Disconnect(_ context.Context, id string) error {
	if !t.m.AdminDisconnect(id) {
		return errSessionGone
	}
	return nil
}

var errSessionGone = errorString("the session ended before the disconnect")

type errorString string

func (e errorString) Error() string { return string(e) }

// jobsOps adapts the job registry to the instance view.
type jobsOps struct{ r *jobs.Registry }

func (j jobsOps) Live() []operations.LiveJob {
	if j.r == nil {
		return nil
	}
	list := j.r.List()
	out := make([]operations.LiveJob, 0, len(list))
	for _, i := range list {
		lj := operations.LiveJob{Name: i.Name, Running: i.Runs > 0, LastRun: i.LastRun, NextRun: i.NextRun}
		if i.LastErr {
			lj.LastErr = "failed"
		}
		out = append(out, lj)
	}
	return out
}

// quotaOps adapts the quota policy to the instance view.
type quotaOps struct{ p *quota.Policy }

func (q quotaOps) Use(context.Context) ([]operations.QuotaUse, error) {
	if q.p == nil {
		return nil, nil
	}
	var out []operations.QuotaUse
	for kind, u := range q.p.Usage() {
		out = append(out, operations.QuotaUse{Kind: kind, Used: u.Used, Limit: u.Global})
	}
	return out, nil
}

// accountNames resolves the owners of the listed connections, sessions
// and transfers; the lists are bounded, so one lookup per id is enough.
type accountNames struct{ sys *system }

func (a accountNames) Usernames(ctx context.Context, ids []int64) (map[int64]string, error) {
	out := make(map[int64]string, len(ids))
	for _, id := range ids {
		acc, err := a.sys.accounts.Get(ctx, id)
		if err != nil {
			continue
		}
		out[id] = acc.Username
	}
	return out, nil
}

// supportFacts are the local facts of the support report.
type supportFacts struct{ sys *system }

func (f supportFacts) Version() string { return buildinfo.Read().Version }

func (f supportFacts) ReadinessFailures(ctx context.Context) []string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return f.sys.edge.ReadinessFailures(ctx)
}

func (f supportFacts) Features(ctx context.Context) map[string]bool {
	out := map[string]bool{"smb": f.sys.cfg.SMB.Enabled}
	if app, err := f.sys.settings.App(ctx); err == nil {
		out["tmux"] = app.RuntimeFeature("tmux_enabled").Enabled
		out["automation"] = app.AutomationEnabled
		out["saved_passwords"] = app.CredentialsEnabled
	}
	for _, name := range operations.Features {
		on, err := f.sys.gates.Active(ctx, name)
		out[name] = err == nil && on
	}
	return out
}

func (f supportFacts) Deployment() operations.SupportDeployment {
	return operations.SupportDeployment{Profile: string(f.sys.cfg.Profile), SecureCookie: f.sys.cfg.Cookies.Secure,
		InternalSSHBlocked: f.sys.cfg.Network.BlockInternalSSH}
}
