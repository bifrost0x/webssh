package settings

import "slices"

// The value sets of the account settings (app/user_settings.py).
var (
	// Themes are the themes an account can choose. Stored values are only
	// checked to be strings, so a theme a later release removed still
	// loads.
	Themes = []string{
		"glass", "werkbank", "retro", "solar", "paper", "noir",
		"arctic-ice", "rose-gold", "cyberpunk-neon", "emerald-matrix", "obsidian",
	}
	StartPages               = []string{"overview", "workspaces"}
	OverviewLayouts          = []string{"dashboard", "classic"}
	OverviewReachabilityMode = []string{"off", "manual", "automatic"}
	DisconnectSessionActions = []string{"retry", "close"}
	// SessionDurations are the sign-in durations in minutes.
	SessionDurations = []int{30, 60, 120, 240, 480}
	// OverviewPanels are the panels of the overview an account can arrange.
	OverviewPanels = []string{"kpis", "topology", "hosts", "attention", "automation", "platforms", "activity", "continue", "agents"}
	// TourStates are the states of the introduction tour.
	TourStates = []string{"completed", "dismissed", "new"}
)

// Defaults of this release for keys without a stored value.
const (
	DefaultTheme                   = "glass"
	DefaultStartPage               = "overview"
	DefaultOverviewLayout          = "dashboard"
	DefaultOverviewReachability    = "manual"
	DefaultDisconnectSessionAction = "retry"
	DefaultSessionDuration         = 30
	DefaultSyncTerminalDirectory   = true
	// DefaultConfirmSessionClose holds for accounts created by this
	// release. Accounts of the Python release with
	// settings_default_generation below 1 had true; the upgrade writes
	// that value explicitly (D-01), see ImportUser.
	DefaultConfirmSessionClose = false
)

const (
	// Overview panel widths are columns of a 12-column grid; heights are
	// in 8px rows, absent or null follows the content.
	panelMinWidth, panelMaxWidth   = 3, 12
	panelMinHeight, panelMaxHeight = 8, 160
	// DismissedLimit bounds the acknowledged attention items.
	DismissedLimit     = 100
	dismissedItemLimit = 160
)

// dismissedKinds are the attention item kinds that can be acknowledged.
var dismissedKinds = []string{"host-keys", "jump-missing", "socks-missing", "unreachable", "credentials", "reboot", "security-updates", "run-failed", "schedule-review"}

// Keys of the account settings. Other stored keys are kept verbatim.
const (
	keyTheme                = "theme"
	keyOverviewLayout       = "overview_layout"
	keyOverviewReachability = "overview_reachability"
	keyOverviewPanels       = "overview_panels"
	keyOverviewDismissed    = "overview_dismissed"
	keyStartPage            = "start_page"
	keyTerminalAppearance   = "terminal_appearance"
	keyConfirmSessionClose  = "confirm_session_close"
	keySyncTerminalDir      = "sync_terminal_directory"
	keyDisconnectAction     = "disconnect_session_action"
	keySessionDuration      = "authentication_session_duration_minutes"
	keyIntroTour            = "intro_tour"
	keyIntroTourV3Ack       = "intro_tour_v3_acknowledged"
	keyRecoveryReviewedAt   = "recovery_reviewed_at"
)

// Keys of a legacy settings.json that other capabilities own: the
// notepad is the note without a host (A05) and the workspace presets
// belong to the hosts (A06). schema_version describes the file only.
const (
	legacyKeyNotepad          = "notepad"
	legacyKeyWorkspacePresets = "workspace_presets"
	legacyKeySchemaVersion    = "schema_version"
)

// legacySettingsSchema is the version of settings.json the import reads
// (CURRENT_STORAGE_VERSIONS['settings']); older files are migrated in
// memory by the legacy reader first.
const legacySettingsSchema = 2

func in[T comparable](set []T, v T) bool { return slices.Contains(set, v) }
