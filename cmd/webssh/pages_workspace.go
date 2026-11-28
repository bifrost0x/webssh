package main

import (
	"context"
	"encoding/json/jsontext"
	"net/http"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/httpapi"
	"github.com/bifrost0x/webssh/internal/session"
	"github.com/bifrost0x/webssh/internal/settings"
)

// inventorySource is what the workspace page draws before the realtime
// connection exists (internal/hosts).
type inventorySource interface {
	Profiles(ctx context.Context, owner int64) ([]jsontext.Value, error)
	JumpHosts(ctx context.Context, owner int64) ([]jsontext.Value, error)
	SOCKSProxies(ctx context.Context, owner int64) ([]jsontext.Value, error)
}

// sessionLookup reads the browser session of a principal
// (internal/session).
type sessionLookup interface {
	Lookup(ctx context.Context, id string) (session.Session, error)
}

// initialInventory is the initial_inventory block of the workspace page.
// Its members are the stored records as the realtime lists return them;
// the renderer encodes the block and fails the page when it cannot.
type initialInventory struct {
	Profiles     []jsontext.Value `json:"profiles"`
	JumpHosts    []jsontext.Value `json:"jump_hosts"`
	SOCKSProxies []jsontext.Value `json:"socks_proxies"`
}

// inventory reads initial_inventory. Like the Python release it gives up
// quietly (the page then asks over the realtime connection, which reports
// storage problems itself).
func (pg *pages) inventory(ctx context.Context, owner int64) any {
	var inv initialInventory
	var err error
	if inv.Profiles, err = pg.inv.Profiles(ctx, owner); err == nil {
		if inv.JumpHosts, err = pg.inv.JumpHosts(ctx, owner); err == nil {
			inv.SOCKSProxies, err = pg.inv.SOCKSProxies(ctx, owner)
		}
	}
	if err != nil {
		pg.log.WarnContext(ctx, "initial host inventory unavailable", "err", err)
		return nil
	}
	for _, list := range []*[]jsontext.Value{&inv.Profiles, &inv.JumpHosts, &inv.SOCKSProxies} {
		if *list == nil {
			*list = []jsontext.Value{}
		}
	}
	return inv
}

// account reads the signed-in account, its page data and its session.
func (pg *pages) account(w http.ResponseWriter, r *http.Request) (httpapi.PageData, *settings.Page, session.Session, bool) {
	u, err := pg.user(r)
	if err == nil && u == nil {
		pg.flow.SignInRequired(r)
		// #nosec G710 -- BasePath is a cleaned local path prefix (no empty segment, so never "//host").
		http.Redirect(w, r, httpapi.BasePath(r)+"/login", http.StatusFound)
		return httpapi.PageData{}, nil, session.Session{}, false
	}
	var d httpapi.PageData
	var page *settings.Page
	var sess session.Session
	if err == nil {
		d, page, err = pg.base(r, u)
	}
	if err == nil {
		sess, err = pg.sessions.Lookup(r.Context(), u.p.SessionID)
	}
	if err != nil {
		pg.failed(w, r, err)
		return httpapi.PageData{}, nil, session.Session{}, false
	}
	d.StartPage, d.OverviewLayout, d.OverviewReachability = page.StartPage, page.OverviewLayout, page.OverviewReachability
	d.SyncTerminalDirectory, d.ConfirmSessionClose = page.SyncTerminalDirectory, page.ConfirmSessionClose
	d.DisconnectSessionAction = page.DisconnectSessionAction
	d.AuthenticationSessionDurationMinutes = page.SessionDurationMinutes
	return d, page, sess, true
}

// workspace is GET / (index).
func (pg *pages) workspace(w http.ResponseWriter, r *http.Request) {
	d, page, sess, ok := pg.account(w, r)
	if !ok {
		return
	}
	panels := page.OverviewPanels
	if len(panels) == 0 {
		panels = jsontext.Value("null")
	}
	d.OverviewPreferences = &httpapi.OverviewPreferences{Panels: panels, Dismissed: page.OverviewDismissed, HostOrder: page.OverviewHostOrder}
	if d.OverviewPreferences.Dismissed == nil {
		d.OverviewPreferences.Dismissed = []string{}
	}
	d.TerminalAppearance = page.TerminalAppearance
	d.ConnectionHistoryScope = page.ConnectionHistoryScope
	d.InitialInventory = pg.inventory(r.Context(), d.User.ID)
	d.MaxEditorFileSize = pg.cfg.Files.MaxEditorBytes
	d.SMBEnabled = pg.cfg.SMB.Enabled
	// The transfer limits as the Python page published them
	// (MAX_UPLOAD_SIZE, MAX_DOWNLOAD_SIZE, MAX_ZIP_DOWNLOAD_SIZE twice).
	t := pg.cfg.Files.Transfers
	d.TransferLimits = httpapi.TransferLimits{UploadBytes: t.MaxUpload, DownloadBytes: t.MaxDownload,
		ArchiveBytes: t.MaxArchive, RemoteTransferBytes: t.MaxArchive}
	d.SSHInputLimits = httpapi.SSHInputLimits{MaxEventBytes: int64(pg.cfg.Terminal.Input.MaxBytes)}
	d.AuthSessionExpiresAt = sess.ExpiresAt.UnixMilli()
	d.AuthServerNow = pg.now().UnixMilli()
	d.Flashes = flashes(pg.flow.TakeFlashes(r))
	pg.write(w, r, http.StatusOK, httpapi.PageWorkspace, d)
}

// methodLabels are the sign-in methods the settings page names, with the
// texts of the Python release.
var methodLabels = map[string][2]string{
	"password":      {"WebSSH password", "security.methodPassword"},
	"ldap":          {"LDAP directory", "security.methodLdap"},
	"oidc":          {"Identity provider (OIDC)", "security.methodOidc"},
	"github":        {"GitHub", "security.methodGithub"},
	"passkey":       {"Passkey", "security.methodPasskey"},
	"totp":          {"Authenticator app", "security.methodTotp"},
	"recovery_code": {"Recovery code", "security.methodRecoveryCode"},
}

// security is GET /security and GET /settings (security_center).
func (pg *pages) security(w http.ResponseWriter, r *http.Request) {
	d, _, sess, ok := pg.account(w, r)
	if !ok {
		return
	}
	methods := sess.Methods
	if len(methods) == 0 {
		methods = []string{"password"}
	}
	for _, m := range methods {
		label, ok := methodLabels[m]
		if !ok {
			label = [2]string{m, "security.methodUnknown"}
		}
		d.AuthenticationMethods = append(d.AuthenticationMethods, httpapi.AuthMethod{ID: m, Label: label[0], I18nKey: label[1]})
	}
	d.AuthenticationPrimaryMethod = methods[0]
	d.RecoveryMode = sess.Recovery()
	acc, err := pg.accounts.Get(r.Context(), d.User.ID)
	if err != nil {
		pg.failed(w, r, err)
		return
	}
	d.AccountMFAEnabled = acc.MFARequired
	d.GitHubManaged = acc.Managed == accounts.ManagedGitHub
	if pg.github != nil && pg.github.githubIdentity != nil {
		id, err := pg.github.githubIdentity(r.Context(), acc.ID)
		if err != nil {
			pg.failed(w, r, err)
			return
		}
		d.GitHubIdentityLinked = id != nil
	}
	pg.write(w, r, http.StatusOK, httpapi.PageSettings, d)
}

// admin is GET /admin: the administration lives on the settings page.
func (pg *pages) admin(w http.ResponseWriter, r *http.Request) {
	// #nosec G710 -- BasePath is a cleaned local path prefix (no empty segment, so never "//host").
	http.Redirect(w, r, httpapi.BasePath(r)+"/security?section=users", http.StatusFound)
}

// register adds the page routes to mux.
func (pg *pages) register(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", pg.workspace)
	mux.HandleFunc("GET /security", pg.security)
	mux.HandleFunc("GET /settings", pg.security)
	mux.HandleFunc("GET /admin", pg.admin)
}
