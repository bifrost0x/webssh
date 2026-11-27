package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/httpapi"
	"github.com/bifrost0x/webssh/internal/realtime"
	"github.com/bifrost0x/webssh/internal/settings"
)

// buildEdges wires the realtime endpoint, the pages and the HTTP edge,
// registers every route and finishes both, so that a route nobody
// registered answers not_available_in_preview.
func (s *system) buildEdges(in bootInput) error {
	cfg := s.cfg
	var err error
	if s.realtime, err = realtime.NewServer(realtimeConfig(s), realtime.Deps{
		Origin:   s.originPolicy(),
		Sessions: s.gatedSessions(), Revocations: s.sessions,
		Limiter: auth.Realtime{L: realtimeLimiter(cfg)}, Auditor: s.audit, Log: s.log,
		Secure: httpapi.ReachedOverHTTPS,
	}); err != nil {
		return fmt.Errorf("realtime endpoint: %w", err)
	}
	s.realtime.Mount(s.terminal.Routes()...)
	s.realtime.Mount(s.hosts.Routes()...)
	s.realtime.Mount(s.notes.Routes()...)
	s.realtime.Mount(s.vault.Routes()...)
	s.realtime.Mount(s.settings.Routes()...)
	s.realtime.HandleBinary(s.terminal.HandleBinary)
	s.realtime.SetRestorer(s.terminal)
	s.realtime.OnKeepalive(s.terminal.Keepalive)
	s.realtime.OnClose(s.terminal.PeerClosed)
	unsubscribe := s.sessions.Subscribe(s.terminal.Revoked)
	s.closers = append(s.closers, func() error { unsubscribe(); return nil })

	assets, err := httpapi.StaticAssets()
	if err != nil {
		return fmt.Errorf("static assets: %w", err)
	}
	renderer, err := httpapi.NewRenderer(assets)
	if err != nil {
		return fmt.Errorf("page templates: %w", err)
	}
	s.pages = &pages{cfg: cfg, renderer: renderer, accounts: s.accounts, settings: s.settings,
		provider: settings.PageProvider{Settings: s.settings, Scope: s.ring}, gates: s.gates, flow: s.flow,
		inv: s.hosts, sessions: s.sessions, tmux: true, github: &s.optional, tailscaleAllowed: s.optional.tailscaleAllowed,
		discoveryAvailable: s.optional.discoveryAvailable, log: s.log, now: time.Now}
	s.edge, err = httpapi.New(httpapi.Options{
		Config: cfg, Sessions: s.gatedSessions(), MAC: s.ring, Assets: assets, Renderer: renderer,
		ErrorPageData: s.pages.errorData,
		Readiness: httpapi.Readiness{Maintenance: s.maintenance.Load, Stopping: in.stopping,
			Database: dbPinger{s.db}, DataDir: cfg.DataDir},
		Logger: s.log,
	})
	if err != nil {
		return fmt.Errorf("http edge: %w", err)
	}
	s.flow.Cookie = s.edge.SessionCookie()
	s.flow.Pages = s.pages
	s.registerHTTP(s.edge.Mux())
	for _, e := range extensions {
		if e.wire != nil {
			if err := e.wire(s); err != nil {
				return fmt.Errorf("extension %s: %w", e.name, err)
			}
		}
	}
	// Finish logs the catalog routes that answer 501 in this build.
	if _, err := s.edge.Finish(); err != nil {
		return fmt.Errorf("http routes: %w", err)
	}
	return nil
}

func realtimeConfig(s *system) realtime.Config {
	t := s.cfg.Terminal
	return realtime.Config{CookieName: s.cfg.Cookies.SessionName, MaxConns: t.MaxConnections, MaxConnsPerUser: t.MaxConnectionsPerUser}
}

// originPolicy is the origin rule of realtime connections (D-20). The
// setting origin.ignore_scheme, which the upgrade wrote for an
// installation behind an untrusted TLS proxy, applies only while the
// current configuration still matches that situation.
func (s *system) originPolicy() *realtime.OriginPolicy {
	o := s.cfg.Origins
	p := &realtime.OriginPolicy{AllowAny: o.AllowAny && o.SkipSameOrigin, Self: httpapi.Origin}
	if !o.AllowAny {
		p.Allowed = o.List
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	app, err := s.settings.App(ctx)
	switch {
	case err != nil:
		s.log.Warn("origin setting unreadable; the scheme is compared", "err", err)
	case app.Policy.OriginIgnoreScheme && keepLegacyScheme(s.cfg):
		p.IgnoreScheme = true
	case app.Policy.OriginIgnoreScheme:
		s.log.Warn("the carried-over setting origin.ignore_scheme has no effect with the current proxy and origin configuration; the scheme is compared")
	}
	return p
}

// handler is the HTTP entry of the server. In maintenance (the legacy
// data changed under a running server, a restore or a rotation) only the
// probes answer, and during a restore the restore status of the
// administration (as in the Python release); every other request,
// realtime connections included, gets 503 maintenance.
func (s *system) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reason, on := s.maintenance.Active()
		if on && !isProbe(s.cfg.ApplicationRoot, r.URL.Path) &&
			(reason != backup.MaintenanceRestore || strings.TrimPrefix(r.URL.Path, s.cfg.ApplicationRoot) != restoreStatusPath) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"success":false,"code":"maintenance","error":"The server is in maintenance mode."}` + "\n"))
			return
		}
		s.edge.ServeHTTP(w, r)
	})
}

// restoreStatusPath stays readable during a restore.
const restoreStatusPath = "/admin/api/backups/restore/status"

func isProbe(root, path string) bool {
	path = strings.TrimPrefix(path, root)
	return path == "/health" || path == "/ready"
}
