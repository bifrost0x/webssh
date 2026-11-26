package settings

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

func newService(t *testing.T, env Environment) (*Service, *store.DB) {
	t.Helper()
	db := storetest.Open(t, Schema())
	return New(db, env), db
}

//go:fix inline

func docJSON(t *testing.T, u User) string {
	t.Helper()
	b, err := json.Marshal(u.Document(), json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDefaults(t *testing.T) {
	s, _ := newService(t, Environment{})
	u, err := s.User(t.Context(), 7)
	if err != nil {
		t.Fatal(err)
	}
	// The defaults of DEFAULT_SETTINGS without the notepad, which is the
	// note without a host in this release.
	const want = `{"authentication_session_duration_minutes":30,"confirm_session_close":false,` +
		`"disconnect_session_action":"retry","overview_dismissed":[],"overview_layout":"dashboard",` +
		`"overview_panels":null,"overview_reachability":"manual","start_page":"overview",` +
		`"sync_terminal_directory":true,"terminal_appearance":{},"theme":"glass"}`
	if got := docJSON(t, u); got != want {
		t.Errorf("defaults\n got %s\nwant %s", got, want)
	}
	if tourState(u) != "new" {
		t.Errorf("tour %q", tourState(u))
	}
}

func TestUpdateReturnsStoredValues(t *testing.T) {
	s, _ := newService(t, Environment{})
	ctx := t.Context()
	u, err := s.Update(ctx, 3, Changes{
		Theme: new("noir"), ConfirmSessionClose: new(true), DisconnectSessionAction: new("close"),
		SessionDurationMinutes: new(480), TerminalAppearance: jsontext.Value(`{"font_size":14}`),
		OverviewPanels:    jsontext.Value(`[{"id":"hosts","w":4,"h":null}]`),
		OverviewDismissed: jsontext.Value(`["reboot:a"]`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if u.Theme != "noir" || !u.ConfirmSessionClose || u.DisconnectSessionAction != "close" || u.SessionDurationMinutes != 480 {
		t.Errorf("stored %+v", u)
	}
	again, err := s.User(ctx, 3)
	if err != nil {
		t.Fatal(err)
	}
	if docJSON(t, again) != docJSON(t, u) {
		t.Errorf("read back differs:\n%s\n%s", docJSON(t, again), docJSON(t, u))
	}
	other, _ := s.User(ctx, 4)
	if other.Theme != DefaultTheme {
		t.Error("settings leaked to another account")
	}
	if string(u.overviewPanelsValue()) != `[{"id":"hosts","w":4,"h":null}]` {
		t.Errorf("panels %s", u.overviewPanelsValue())
	}
	u, _ = s.Update(ctx, 3, Changes{OverviewPanels: jsontext.Value("null")})
	if u.OverviewPanels != nil {
		t.Error("null did not restore the default layout")
	}
}

func TestUpdateRefusesInvalidValues(t *testing.T) {
	s, _ := newService(t, Environment{})
	cases := map[string]Changes{
		msgInvalidTheme:      {Theme: new("removed")},
		msgInvalidStartPage:  {StartPage: new("files")},
		msgInvalidLayout:     {OverviewLayout: new("grid")},
		msgInvalidReach:      {OverviewReachability: new("always")},
		msgInvalidDisconnect: {DisconnectSessionAction: new("reconnect")},
		msgInvalidDuration:   {SessionDurationMinutes: new(45)},
		msgInvalidAppearance: {TerminalAppearance: jsontext.Value(`{"font_size":99}`)},
		msgInvalidPanels:     {OverviewPanels: jsontext.Value(`[{"id":"x","w":4}]`)},
		msgInvalidDismissed:  {OverviewDismissed: jsontext.Value(`["x:y"]`)},
		msgInvalidTourState:  {Tour: new("later")},
		msgNothingToChange:   {},
	}
	for want, c := range cases {
		_, err := s.Update(t.Context(), 1, c)
		var f *fault.Error
		if !errors.As(err, &f) || f.Message != want {
			t.Errorf("%s: %v", want, err)
		}
	}
	// A refused change leaves every value as it was, also those of the
	// same request that were valid.
	if _, err := s.Update(t.Context(), 1, Changes{Theme: new("noir"), StartPage: new("files")}); err == nil {
		t.Fatal("accepted")
	}
	if u, _ := s.User(t.Context(), 1); u.Theme != DefaultTheme {
		t.Error("a refused request stored a value")
	}
}

func TestCorruptRowFailsClosed(t *testing.T) {
	s, db := newService(t, Environment{})
	err := db.Write(t.Context(), func(tx *store.Tx) error {
		_, err := tx.ExecContext(context.Background(), `INSERT INTO settings_user VALUES (1, 'theme', '5')`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.User(t.Context(), 1); !fault.Is(err, fault.StorageError) {
		t.Errorf("corrupt value: %v", err)
	}
}

func TestReadFiltersOverviewEntries(t *testing.T) {
	_, db := newService(t, Environment{})
	err := db.Write(t.Context(), func(tx *store.Tx) error {
		if err := putUser(t.Context(), tx, 1, keyOverviewPanels, jsontext.Value(`[{"id":"future","w":4},{"id":"kpis","w":6}]`)); err != nil {
			return err
		}
		return putUser(t.Context(), tx, 1, keyOverviewDismissed, jsontext.Value(`["future:x","reboot:a","reboot:a"]`))
	})
	if err != nil {
		t.Fatal(err)
	}
	s := New(db, Environment{})
	u, err := s.User(t.Context(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(u.overviewPanelsValue()) != `[{"id":"kpis","w":6}]` || len(u.OverviewDismissed) != 1 {
		t.Errorf("kept %s %v", u.overviewPanelsValue(), u.OverviewDismissed)
	}
}

func TestOnboarding(t *testing.T) {
	s, _ := newService(t, Environment{})
	ctx := t.Context()
	if err := s.SetOnboarding(ctx, 2, "dismissed", false); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.User(ctx, 2); tourState(u) != "dismissed" {
		t.Error("dismissed tour")
	}
	if err := s.SetOnboarding(ctx, 2, "new", true); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.User(ctx, 2); tourState(u) != "completed" {
		t.Error("acknowledged tour")
	}
	if err := s.SetOnboarding(ctx, 2, "bogus", true); err == nil {
		t.Error("unknown tour state accepted")
	}
}

func TestDeleteUser(t *testing.T) {
	s, db := newService(t, Environment{})
	ctx := t.Context()
	if _, err := s.Update(ctx, 5, Changes{Theme: new("noir")}); err != nil {
		t.Fatal(err)
	}
	if err := db.Write(ctx, func(tx *store.Tx) error { return DeleteUser(ctx, tx, 5) }); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.User(ctx, 5); u.Theme != DefaultTheme {
		t.Error("settings survived the account")
	}
}
