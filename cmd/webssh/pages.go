package main

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/buildinfo"
	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/httpapi"
	"github.com/bifrost0x/webssh/internal/operations"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/settings"
)

// pages renders the server-side pages. It fills httpapi.PageData from
// the capabilities: the context processor values of the Python release
// for every page, and the page's own values for the workspace and the
// settings page (pages_workspace.go).
type pages struct {
	cfg      config.Config
	renderer *httpapi.Renderer
	accounts *accounts.Service
	settings *settings.Service
	provider settings.PageProvider
	gates    *operations.Gates
	flow     *auth.Flow
	inv      inventorySource
	sessions sessionLookup
	// tmux says whether the terminal runs persistent tmux sessions; the
	// tmux switches of the pages follow the runtime setting only then.
	tmux bool
	// github is the area "github" (sys.optional); nil: not in the build.
	github *optional
	// tailscaleAllowed is user_can_use_tailscale_ssh; nil offers no
	// Tailscale SSH.
	tailscaleAllowed func(principal.Principal) bool
	// discoveryAvailable is host_discovery_available; nil offers no
	// discovery.
	discoveryAvailable func(context.Context, principal.Principal) bool
	log                *slog.Logger
	now                func() time.Time
}

// signedIn is the account behind a request's principal.
type signedIn struct {
	p   principal.Principal
	acc accounts.Account
}

// user returns the signed-in account of r, if any. A principal whose
// account cannot be read fails the page instead of showing it anonymous.
func (pg *pages) user(r *http.Request) (*signedIn, error) {
	p, ok := principal.From(r.Context())
	if !ok {
		return nil, nil
	}
	acc, err := pg.accounts.Get(r.Context(), p.UserID)
	if err != nil {
		return nil, err
	}
	return &signedIn{p: p, acc: acc}, nil
}

// base returns the values every page reads (inject_url_prefix of the
// Python release) and, for a signed-in account, its theme and scope.
func (pg *pages) base(r *http.Request, u *signedIn) (httpapi.PageData, *settings.Page, error) {
	ctx := r.Context()
	app, err := pg.settings.App(ctx)
	if err != nil {
		return httpapi.PageData{}, nil, err
	}
	bootstrap, err := pg.bootstrapOpen(ctx)
	if err != nil {
		return httpapi.PageData{}, nil, err
	}
	d := httpapi.PageData{
		BasePath:                 httpapi.BasePath(r),
		URLPrefix:                pg.cfg.ApplicationRoot,
		CSRFToken:                httpapi.CSRFToken(r),
		Theme:                    "glass",
		RegistrationEnabled:      app.RegistrationEnabled || bootstrap,
		AdminPanelEnabled:        pg.cfg.Accounts.AdminPanelEnabled,
		AuditExportEnabled:       pg.cfg.Audit.ExportEnabled,
		WebAuthnEnabled:          pg.active(ctx, "passkey"),
		WebAuthnOrigin:           pg.cfg.WebAuthn.Origin,
		WebAuthnRPID:             pg.cfg.WebAuthn.RPID,
		TOTPEnabled:              pg.active(ctx, "totp"),
		OIDCEnabled:              pg.active(ctx, "oidc"),
		RecoveryCodesEnabled:     pg.active(ctx, "recovery"),
		HostKeyManagementEnabled: pg.cfg.Features.HostKeyManagement,
		LDAPEnabled:              pg.active(ctx, "ldap"),
		LDAPProviderID:           pg.cfg.LDAP.ProviderID,
		GitHubAuthEnabled:        pg.github != nil && pg.github.githubActive != nil && pg.github.githubActive(ctx),
		SSHGatewayEnabled:        app.SSHGatewayEnabled,
		HerdrEnabled:             app.HerdrEnabled,
		AutomationEnabled:        app.AutomationEnabled,
		Preview:                  previewNotice(u == nil),
	}
	if u == nil {
		return d, nil, nil
	}
	page, err := pg.provider.Page(ctx, settings.Account{ID: u.acc.ID, Username: u.acc.Username, HistoryGeneration: u.acc.HistoryGeneration})
	if err != nil {
		return httpapi.PageData{}, nil, err
	}
	d.User = httpapi.User{ID: u.acc.ID, Username: u.acc.Username, IsAdmin: u.p.IsAdmin, Authenticated: true}
	d.LDAPManaged = u.acc.Managed == accounts.ManagedLDAP
	d.Theme = page.Theme
	d.BackgroundScope = page.ConnectionHistoryScope
	d.WebSSHVersion = buildinfo.Read().Version
	d.SupportLinksEnabled = app.SupportLinksEnabled
	d.TailscaleSSHAllowed = pg.tailscaleAllowed != nil && pg.tailscaleAllowed(u.p)
	d.HostDiscoveryAvailable = pg.discoveryAvailable != nil && pg.discoveryAvailable(ctx, u.p)
	d.TmuxEnabled = pg.tmux && page.TmuxEnabled
	d.TmuxDefault = pg.tmux && page.TmuxDefault
	d.LegacySSHOptIn = page.LegacySSHOptIn
	return d, &page, nil
}

func (pg *pages) bootstrapOpen(ctx context.Context) (bool, error) {
	if !pg.cfg.Accounts.BootstrapRegistrationEnabled {
		return false, nil
	}
	has, err := pg.accounts.HasAccounts(ctx)
	return !has, err
}

// active is feature_is_active; a failure counts as inactive (fail
// closed), as operations.Gates.Active does.
func (pg *pages) active(ctx context.Context, feature string) bool {
	ok, err := pg.gates.Active(ctx, feature)
	return err == nil && ok
}

func flashes(fs []auth.Flash) []httpapi.Flash {
	out := make([]httpapi.Flash, 0, len(fs))
	for _, f := range fs {
		out = append(out, httpapi.Flash{Category: f.Category, Message: f.Message})
	}
	return out
}

// write renders page with status. A render failure is logged and answered
// with a plain 500; nothing of the page has been written then.
func (pg *pages) write(w http.ResponseWriter, r *http.Request, status int, page httpapi.Page, d httpapi.PageData) {
	var buf bytes.Buffer
	if err := pg.renderer.Render(&buf, page, d); err != nil {
		pg.log.ErrorContext(r.Context(), "render page", "page", string(page), "err", err)
		http.Error(w, "An internal error occurred.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// failed answers a page whose data could not be read.
func (pg *pages) failed(w http.ResponseWriter, r *http.Request, err error) {
	pg.log.ErrorContext(r.Context(), "page data", "path", r.URL.Path, "err", err)
	http.Error(w, "An internal error occurred.", http.StatusInternalServerError)
}

// Login, Register, ChangePassword and Error implement auth.Pages.

func (pg *pages) Login(w http.ResponseWriter, r *http.Request, status int, v auth.LoginView) {
	d, _, err := pg.base(r, nil)
	if err != nil {
		pg.failed(w, r, err)
		return
	}
	d.Flashes, d.AuthSource, d.MFARequired, d.MFAMethods = flashes(v.Flashes), v.AuthSource, v.MFARequired, v.MFAMethods
	d.LDAPError = v.LDAPError
	pg.write(w, r, status, httpapi.PageLogin, d)
}

func (pg *pages) Register(w http.ResponseWriter, r *http.Request, status int, v auth.FormView) {
	pg.form(w, r, status, httpapi.PageRegister, v)
}

func (pg *pages) ChangePassword(w http.ResponseWriter, r *http.Request, status int, v auth.FormView) {
	pg.form(w, r, status, httpapi.PageChangePassword, v)
}

func (pg *pages) form(w http.ResponseWriter, r *http.Request, status int, page httpapi.Page, v auth.FormView) {
	u, err := pg.user(r)
	if err != nil {
		pg.failed(w, r, err)
		return
	}
	d, _, err := pg.base(r, u)
	if err != nil {
		pg.failed(w, r, err)
		return
	}
	d.Flashes = flashes(v.Flashes)
	pg.write(w, r, status, page, d)
}

func (pg *pages) Error(w http.ResponseWriter, r *http.Request, status int) {
	d := pg.errorData(r)
	d.Status = status
	switch status {
	case http.StatusForbidden:
		d.Kind = "forbidden"
	case http.StatusNotFound:
		d.Kind = "not_found"
	}
	d.ActionURL = d.BasePath + "/"
	pg.write(w, r, status, httpapi.PageError, d)
}

// errorData is the base of the error page: the theme of a signed-in user
// when it can be read, otherwise the defaults (_error_page).
func (pg *pages) errorData(r *http.Request) httpapi.PageData {
	d := httpapi.PageData{BasePath: httpapi.BasePath(r), URLPrefix: pg.cfg.ApplicationRoot, Theme: "glass"}
	if p, ok := principal.From(r.Context()); ok {
		if s, err := pg.settings.User(r.Context(), p.UserID); err == nil && s.Theme != "" {
			d.Theme = s.Theme
		}
	}
	return d
}
