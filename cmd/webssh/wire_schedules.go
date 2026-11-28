package main

import (
	"context"
	"io/fs"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/audit"
	"github.com/bifrost0x/webssh/internal/automation"
	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/httpapi"
	"github.com/bifrost0x/webssh/internal/jobs"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/quota"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/session"
	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/vault"
)

// schedulesArea wires the area "schedules" (AU2): automation schedules and permission jobs (internal/automation).
//
// The schedules review and run through the run side of automation
// (scheduleWorkflows); without it they can be listed, paused and deleted,
// and no due slot is touched, so migrated schedules keep their approval.
func schedulesArea() extension {
	return extension{
		name: "schedules",
		wire: wireSchedules,
		migrate: func(r *legacy.Registry, _ config.Config, _ config.LookupFunc) error {
			return legacy.AddSchedules(r)
		},
	}
}

// scheduleWorkflows returns the run side of automation, which the
// automation area (wired before this one) provides.
func scheduleWorkflows(sys *system) automation.ScheduleWorkflows {
	if sys.automation == nil {
		return nil
	}
	return sys.automation.Workflows()
}

// scheduleCancel settles the claim of a scheduled run that the run side
// cancels while it is not active in this process.
type scheduleCancel struct{ s *automation.Schedules }

func (c scheduleCancel) CancelRun(ctx context.Context, userID int64, scheduleID, claimID string) error {
	_, err := c.s.CancelRun(ctx, userID, scheduleID, claimID)
	return err
}

func wireSchedules(sys *system) error {
	draining := func() bool { return sys.maintenance.Load() }
	sched, err := automation.NewSchedules(automation.ScheduleOptions{
		DB: sys.db, Workflows: scheduleWorkflows(sys), Accounts: scheduleAccounts{sys.accounts, sys.sessions},
		Policy: schedulePolicy{sys.settings}, Passwords: sys.vault, StepUp: sys.stepup, Audit: sys.audit,
		Draining: draining,
	})
	if err != nil {
		return err
	}
	sys.schedules = sched
	secure := httpapi.ReachedOverHTTPS
	if sys.automationHTTP != nil {
		secure = sys.automationHTTP.Secure
	}
	(&automation.SchedulesHTTP{Schedules: sched, Secure: secure, Logger: sys.log}).Register(sys.edge.Mux())
	if sys.automation != nil {
		sys.automation.SetSchedules(scheduleCancel{sched})
	}
	if sched.Runs() {
		if err := sys.jobs.Register("automation.schedules", jobs.Spec{Every: automation.ScheduleTickInterval, Singleton: true,
			Timeout: time.Minute}, sched.Tick); err != nil {
			return err
		}
	}
	perms, err := automation.NewPermissionJobs(automation.PermOptions{
		Sources: permSources{reg: sys.fileSources, settings: sys.settings, maxPath: sys.cfg.Files.MaxPathBytes}, Quotas: sys.quotas,
		Audit: permAudit{reg: sys.fileSources, log: sys.audit}, Draining: draining,
	})
	if err != nil {
		return err
	}
	sys.realtime.Mount(perms.Routes()...)
	sys.realtime.OnClose(func(p protocol.Peer) { perms.PeerClosed(p.Principal().UserID, p.ID()) })
	unsubscribe := sys.sessions.Subscribe(func(rev principal.Revocation) {
		sched.Revoke(rev)
		perms.Revoke(rev)
	})
	sys.closers = append(sys.closers, func() error {
		unsubscribe()
		ctx, cancel := context.WithTimeout(context.Background(), jobs.MaxShutdownGrace)
		defer cancel()
		return perms.Shutdown(ctx)
	})
	return nil
}

// The providers satisfy the consumer interfaces of the area.
var (
	_ automation.SchedulePasswords = (*vault.Service)(nil)
	_ automation.ScheduleAudit     = (*audit.Logger)(nil)
	_ automation.PermQuotas        = (*quota.Policy)(nil)
	_ automation.ScheduleAccounts  = scheduleAccounts{}
	_ automation.SchedulePolicy    = schedulePolicy{}
	_ automation.PermSources       = permSources{}
	_ automation.PermAudit         = permAudit{}
)

// scheduleAccounts binds approvals to the account and to the
// installation's sign-out generation.
type scheduleAccounts struct {
	accounts *accounts.Service
	sessions *session.Service
}

func (a scheduleAccounts) ScheduleAccount(ctx context.Context, userID int64) (automation.AccountBinding, error) {
	acc, err := a.accounts.Get(ctx, userID)
	if err != nil {
		return automation.AccountBinding{}, err
	}
	epoch, err := a.sessions.Epoch(ctx)
	if err != nil {
		return automation.AccountBinding{}, err
	}
	return automation.AccountBinding{Incarnation: acc.Incarnation, AuthGeneration: acc.AuthGeneration, Epoch: epoch,
		Locked: acc.IsLocked}, nil
}

type schedulePolicy struct{ settings *settings.Service }

func (p schedulePolicy) AutomationPolicy(ctx context.Context) (bool, string, error) {
	app, err := p.settings.App(ctx)
	return app.AutomationEnabled, app.AutomationRevision, err
}

// permSources holds the file sources of the workspace for permission
// changes while SFTP_CHMOD_ENABLED is on (read per request, as Python).
type permSources struct {
	reg      *files.Registry
	settings *settings.Service
	// maxPath is FILE_CONTROL_MAX_PATH_BYTES.
	maxPath int
}

func (s permSources) Hold(ctx context.Context, p principal.Principal, sourceID string) (automation.PermSource, any, func(), error) {
	app, err := s.settings.App(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	if !app.RuntimeFeature("sftp_chmod_enabled").Enabled {
		return nil, nil, nil, fault.New(fault.UnsupportedOperation, "")
	}
	b, release, err := s.reg.Resolve(ctx, p, sourceID, files.CapChmod)
	if err != nil {
		return nil, nil, nil, err
	}
	return permBackend{b}, b, release, nil
}

func (s permSources) Clean(path string) (string, error) {
	if s.maxPath > 0 && len(path) > s.maxPath {
		return "", fault.New(fault.InvalidRequest, "The path is invalid.")
	}
	return files.CleanTarget(path)
}

// permBackend is a files.Backend as a permission source.
type permBackend struct{ b files.Backend }

func (p permBackend) Lstat(ctx context.Context, path string) (automation.PermEntry, error) {
	e, err := p.b.Stat(ctx, path, false)
	if err != nil {
		return automation.PermEntry{}, err
	}
	out := automation.PermEntry{Mode: e.Mode, Size: e.Size, ModTime: e.ModTime}
	if e.Owner != nil {
		uid, gid := e.Owner.UID, e.Owner.GID
		out.UID, out.GID = &uid, &gid
	}
	return out, nil
}

// LoginUID is the owner of the login directory: the account the source
// signed in as. Without an owner the safe-path rule of the permission
// jobs cannot hold, so the job is refused (UNSAFE_PATH).
func (p permBackend) LoginUID(ctx context.Context) (uint32, error) {
	home, err := p.b.Home(ctx)
	if err != nil {
		return 0, err
	}
	e, err := p.b.Stat(ctx, home, false)
	if err != nil {
		return 0, err
	}
	if e.Owner == nil {
		return 0, fault.New(fault.UnsafePath, "")
	}
	return e.Owner.UID, nil
}

func (p permBackend) Children(ctx context.Context, dir string, fn func(string) error) error {
	l, err := p.b.OpenListing(ctx, dir)
	if err != nil {
		return err
	}
	defer l.Close()
	for {
		entries, more, err := l.Next(ctx, 512)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := fn(e.Name); err != nil {
				return err
			}
		}
		if !more {
			return nil
		}
	}
}

// expectChmoder is a backend that ties a permission change to the object
// the caller inspected (SFTP: on a handle for regular files).
type expectChmoder interface {
	ChmodExpect(ctx context.Context, path string, perm fs.FileMode, want files.Entry) error
}

func (p permBackend) Chmod(ctx context.Context, path string, perm uint32, want automation.PermEntry) error {
	mode := fs.FileMode(perm) & fs.ModePerm
	b, ok := p.b.(expectChmoder)
	if !ok {
		return p.b.Chmod(ctx, path, mode)
	}
	e := files.Entry{Mode: want.Mode, Size: want.Size, ModTime: want.ModTime}
	if want.UID != nil && want.GID != nil {
		e.Owner = &files.Owner{UID: *want.UID, GID: *want.GID}
	}
	return b.ChmodExpect(ctx, path, mode, e)
}

// permAudit writes FILE_SOURCE_OPERATION with the target fields of the
// source, as the file workspace does.
type permAudit struct {
	reg *files.Registry
	log *audit.Logger
}

func (a permAudit) PermissionChange(p principal.Principal, sourceID, operation, result, path, oldMode, newMode string) {
	if a.log == nil {
		return
	}
	d, _, _ := a.reg.Describe(p, sourceID)
	name := path
	if i := strings.LastIndexByte(path, '/'); i >= 0 && path != "/" {
		name = path[i+1:]
	}
	a.log.Security("FILE_SOURCE_OPERATION", "user", p.Username, "operation", operation, "result", result,
		"source_kind", "sftp", "target_host", d.Endpoint, "share", nil, "filename", name, "size", 0,
		"old_mode", oldMode, "new_mode", newMode)
}
