package main

import (
	"context"
	"net/http"
	"time"

	"github.com/bifrost0x/webssh/internal/audit"
	"github.com/bifrost0x/webssh/internal/auth/stepup"
	"github.com/bifrost0x/webssh/internal/automation"
	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/hosts"
	"github.com/bifrost0x/webssh/internal/httpapi"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
	"github.com/bifrost0x/webssh/internal/quota"
	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/ssh/hostkey"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/vault"
)

// automationArea wires the area "automation" (AU1): automation runbooks and runs (internal/automation).
// AU1 fills in the hooks; no other package edits this file.
func automationArea() extension {
	return extension{
		name:    "automation",
		schemas: []store.Schema{automation.Schema()},
		wire: func(sys *system) error {
			svc, err := automation.New(automation.Options{
				DB:        sys.db,
				Records:   credentialStores{db: sys.db},
				Passwords: sys.vault,
				Keys:      automationKeys{sys.vault},
				HostTrust: automationTrust{sys.hostkeys},
				Resolver:  sys.hosts,
				Dialer:    automationDialer{sys.shells},
				Switches:  automationSwitches{sys.settings},
				Quotas:    sys.quotas,
				StepUp:    sys.stepup,
				Audit:     sys.audit,
				Facts:     automationFacts{sys.hosts},
				Accepting: func() bool { return !sys.maintenance.Load() },
				Logger:    sys.log,
			})
			if err != nil {
				return err
			}
			sys.automation = svc
			cfg := sys.cfg
			(&automation.HTTP{Service: svc, HTTPS: httpapi.ReachedOverHTTPS,
				InsecureLoopback: cfg.Debug && cfg.Profile == config.ProfileHomelab && cfg.Features.AutomationInsecureLoopback,
				Proxied:          cfg.Proxies.Hops > 0,
				Index:            func(r *http.Request) string { return httpapi.BasePath(r) + "/" },
				Logger:           sys.log}).Register(sys.edge.Mux())
			unsubscribe := sys.sessions.Subscribe(svc.Revoked)
			sys.closers = append(sys.closers, func() error {
				unsubscribe()
				ctx, cancel := context.WithTimeout(context.Background(), sys.shutdownGrace())
				defer cancel()
				return svc.Shutdown(ctx)
			})
			return nil
		},
		background: func(ctx context.Context, sys *system) {
			sys.background.Go(func() {
				sys.every(ctx, 5*time.Second, func(context.Context) bool {
					sys.automation.Sweep()
					return true
				})
			})
		},
		migrate: func(r *legacy.Registry, _ config.Config, _ config.LookupFunc) error {
			return legacy.AddAutomation(r)
		},
	}
}

// The providers satisfy the consumer interfaces of the area.
var (
	_ automation.Records   = credentialStores{}
	_ automation.Passwords = (*vault.Service)(nil)
	_ automation.Keys      = automationKeys{}
	_ automation.HostTrust = automationTrust{}
	_ automation.Resolver  = (*hosts.Service)(nil)
	_ automation.Dialer    = automationDialer{}
	_ automation.Switches  = automationSwitches{}
	_ automation.Quotas    = (*quota.Policy)(nil)
	_ automation.StepUp    = (*stepup.Service)(nil)
	_ automation.Auditor   = (*audit.Logger)(nil)
	_ automation.Facts     = automationFacts{}
)

// automationKeys binds a run to the public key of each stored key it
// signs in with: replacing the key changes it.
type automationKeys struct{ vault *vault.Service }

func (k automationKeys) PublicKey(ctx context.Context, owner int64, keyID string) ([]byte, error) {
	s, err := k.vault.Signer(ctx, owner, keyID)
	if err != nil {
		return nil, err
	}
	return s.PublicKey().Marshal(), nil
}

// automationTrust is has_trusted_key: a key that is not revoked applies
// to the endpoint, from the user's or the global trust.
type automationTrust struct{ store *hostkey.Store }

func (t automationTrust) Trusted(ctx context.Context, owner int64, host string, port int) (bool, error) {
	reports, err := t.store.Effective(ctx, owner, []hostkey.Target{{Host: host, Port: port, Kind: "ssh"}})
	if err != nil {
		return false, err
	}
	for _, r := range reports {
		for _, k := range r.Keys {
			if k.Status == "effective" {
				return true, nil
			}
		}
	}
	return false, nil
}

// automationDialer opens a run's connection through the shared dialer
// with the per-host legacy algorithm rule.
type automationDialer struct{ shells legacyAlgorithmShells }

func (d automationDialer) Dial(ctx context.Context, t client.Target, ix client.Interaction) (automation.Conn, error) {
	conn, err := d.shells.Dial(ctx, t, ix)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// automationSwitches reads automation_enabled (with AUTOMATION_ENABLED)
// and credentials_enabled.
type automationSwitches struct{ s *settings.Service }

func (w automationSwitches) AutomationEnabled(ctx context.Context) (bool, error) {
	app, err := w.s.App(ctx)
	return err == nil && app.AutomationEnabled, err
}

func (w automationSwitches) CredentialsEnabled(ctx context.Context) (bool, error) {
	app, err := w.s.App(ctx)
	return err == nil && app.CredentialsEnabled, err
}

// automationFacts stores the update and restart facts of a run of the
// read-only maintenance check (_record_maintenance_facts).
type automationFacts struct{ hosts *hosts.Service }

func (f automationFacts) StepFinished(ctx context.Context, owner int64, profileID string, l automation.Login, step automation.Step, r automation.StepResult) error {
	exit := -1
	if r.ExitCode != nil {
		exit = int(*r.ExitCode)
	}
	m, ok := hosts.MaintenanceOfRun(step.Command, step.Sudo, r.Status == automation.StatusSucceeded, exit, r.Truncated, r.Stdout)
	if !ok {
		return nil
	}
	_, err := f.hosts.CacheMaintenance(ctx, owner, profileID, hosts.Login{Host: l.Host, Port: l.Port, User: l.User, JumpHostID: l.JumpHostID}, m, time.Now())
	return err
}
