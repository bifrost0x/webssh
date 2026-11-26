package settings

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"

	"github.com/bifrost0x/webssh/internal/fault"
)

// Scoper derives the namespace of an account's browser-local data;
// *keyring.Ring provides it (A04, D-10).
type Scoper interface {
	BrowserScope(userID int64, username, generation string) string
}

// Account identifies the signed-in account for the page values.
// HistoryGeneration is the frozen generation of the account
// (accounts_users.history_generation): the ISO form of created_at, or the
// legacy password hash for accounts without created_at.
type Account struct {
	ID                int64
	Username          string
	HistoryGeneration string
}

// Page are the settings values of the server-rendered pages. The
// composition root copies them into the page data.
type Page struct {
	Theme                string
	StartPage            string
	OverviewLayout       string
	OverviewReachability string
	// OverviewPanels is the effective arrangement (JSON null or array) and
	// OverviewDismissed the acknowledged items, as checked values.
	OverviewPanels    jsontext.Value
	OverviewDismissed []string
	// OverviewPreferencesJSON is {"panels", "dismissed"} encoded exactly as
	// the Jinja filter tojson of the Python release; the page block
	// #overviewPreferences must carry these bytes.
	OverviewPreferencesJSON string
	// TerminalAppearance is the override object; TerminalAppearanceJSON is
	// its tojson form for data-terminal-appearance.
	TerminalAppearance      map[string]any
	TerminalAppearanceJSON  string
	SyncTerminalDirectory   bool
	ConfirmSessionClose     bool
	DisconnectSessionAction string
	SessionDurationMinutes  int
	// ConnectionHistoryScope is also the background scope of the page.
	ConnectionHistoryScope string

	SupportLinksEnabled bool
	SSHGatewayEnabled   bool
	HerdrEnabled        bool
	RegistrationEnabled bool
	AutomationEnabled   bool
	TmuxEnabled         bool
	TmuxDefault         bool
	SFTPChmodEnabled    bool
}

// PageProvider computes the page values of an account.
type PageProvider struct {
	Settings *Service
	Scope    Scoper
}

// errNoGeneration refuses a page without the account's generation: an
// empty one would let a reused account id inherit browser data.
var errNoGeneration = errors.New("settings: account without history generation")

// Page returns the values for acct. Encoding errors fail the page
// instead of rendering a placeholder.
func (pp PageProvider) Page(ctx context.Context, acct Account) (Page, error) {
	if acct.ID <= 0 || acct.HistoryGeneration == "" || pp.Scope == nil {
		return Page{}, fault.Wrap(fault.Internal, errNoGeneration, "")
	}
	u, err := pp.Settings.User(ctx, acct.ID)
	if err != nil {
		return Page{}, err
	}
	app, err := pp.Settings.App(ctx)
	if err != nil {
		return Page{}, err
	}
	p := Page{
		Theme: u.Theme, StartPage: u.StartPage, OverviewLayout: u.OverviewLayout,
		OverviewReachability: u.OverviewReachability, OverviewPanels: u.overviewPanelsValue(),
		OverviewDismissed: u.OverviewDismissed, SyncTerminalDirectory: u.SyncTerminalDirectory,
		ConfirmSessionClose: u.ConfirmSessionClose, DisconnectSessionAction: u.DisconnectSessionAction,
		SessionDurationMinutes: u.SessionDurationMinutes,
		ConnectionHistoryScope: pp.Scope.BrowserScope(acct.ID, acct.Username, acct.HistoryGeneration),
		SupportLinksEnabled:    app.SupportLinksEnabled, SSHGatewayEnabled: app.SSHGatewayEnabled,
		HerdrEnabled: app.HerdrEnabled, RegistrationEnabled: app.RegistrationEnabled,
		AutomationEnabled: app.AutomationEnabled,
		TmuxEnabled:       app.RuntimeFeature("tmux_enabled").Enabled,
		TmuxDefault:       app.RuntimeFeature("tmux_default").Enabled,
		SFTPChmodEnabled:  app.RuntimeFeature("sftp_chmod_enabled").Enabled,
	}
	prefs, err := json.Marshal(map[string]any{"panels": p.OverviewPanels, "dismissed": p.OverviewDismissed})
	if err != nil {
		return Page{}, fault.Wrap(fault.Internal, err, "")
	}
	if p.OverviewPreferencesJSON, err = PythonJSON(prefs); err != nil {
		return Page{}, fault.Wrap(fault.Internal, err, "")
	}
	if p.TerminalAppearanceJSON, err = PythonJSON(u.TerminalAppearance); err != nil {
		return Page{}, fault.Wrap(fault.Internal, err, "")
	}
	if err := json.Unmarshal(u.TerminalAppearance, &p.TerminalAppearance); err != nil {
		return Page{}, fault.Wrap(fault.Internal, err, "")
	}
	return p, nil
}
