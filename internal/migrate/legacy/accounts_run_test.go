package legacy

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"maps"
	"testing"

	"github.com/bifrost0x/webssh/internal/store"
)

// Running the account steps one account at a time gives the report and
// the data of a run over all accounts at once, on every golden data
// directory and with the complete registry of this package.
func TestAccountByAccountMatchesWholeSource(t *testing.T) {
	t.Parallel()
	sources := map[string]func(*testing.T) (string, string){
		"golden": func(t *testing.T) (string, string) { return copyGolden(t), golden.manifest.SecretKey.Value },
	}
	for _, archive := range []string{"datadir-extended.tar", "datadir-v1.0.0.tar", "datadir-2fcd38a.tar"} {
		sources[archive] = func(t *testing.T) (string, string) {
			return extractLegacy(t, archive), legacyFixture(t).SecretKey.Value
		}
	}
	for name, source := range sources {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var reports [2][]StepReport
			var tables [2]map[string]int
			for i, whole := range []bool{false, true} {
				dir, secret := source(t)
				o := testOptions(t, dir)
				o.Registry, o.Secret, o.wholeSource = restoreRegistry(t), secret, whole
				st, err := startClosed(o)
				if err != nil || !st.Migrated {
					t.Fatalf("whole source %v: %+v, %v", whole, st, err)
				}
				reports[i] = st.Report.Entities
				tables[i] = rowCounts(t, dir)
			}
			if len(reports[0]) != len(reports[1]) {
				t.Fatalf("%d entities account by account, %d over the whole source", len(reports[0]), len(reports[1]))
			}
			for i := range reports[0] {
				a, _ := json.Marshal(reports[0][i], json.Deterministic(true))
				b, _ := json.Marshal(reports[1][i], json.Deterministic(true))
				if string(a) != string(b) {
					t.Errorf("report differs:\n account by account %s\n whole source       %s", a, b)
				}
			}
			if !maps.Equal(tables[0], tables[1]) {
				t.Errorf("rows differ: %v vs %v", tables[0], tables[1])
			}
		})
	}
}

// rowCounts counts the rows of every table of the migrated database.
func rowCounts(t *testing.T, dir string) map[string]int {
	t.Helper()
	out := map[string]int{}
	withDB(t, dir, func(tx *store.Tx) error {
		rows, err := tx.QueryContext(t.Context(), `SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name`)
		if err != nil {
			return err
		}
		var names []string
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				return err
			}
			names = append(names, n)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return err
		}
		for _, n := range names {
			var c int
			if err := tx.QueryRowContext(t.Context(), `SELECT count(*) FROM "`+n+`"`).Scan(&c); err != nil {
				return err
			}
			out[n] = c
		}
		return nil
	})
	return out
}

// An account step sees only the account in scope, and the host stores
// read for one account are released before the next.
func TestScopeLimitsAccountsAndReleasesHosts(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	src, err := Open(context.Background(), dir, golden.manifest.SecretKey.Value)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	all, err := src.AccountRows(t.Context())
	if err != nil || len(all) < 2 {
		t.Fatalf("%d accounts, %v", len(all), err)
	}
	src.scopeTo(all[1:2], true)
	got, err := src.AccountRows(t.Context())
	if err != nil || len(got) != 1 || got[0].ID != all[1].ID {
		t.Fatalf("scoped rows %v, %v", got, err)
	}
	if _, err := readUserHosts(t.Context(), src); err != nil || src.hosts == nil {
		t.Fatalf("hosts not read: %v", err)
	}
	src.scopeTo(nil, true)
	if got, _ := src.AccountRows(t.Context()); len(got) != 0 || src.hosts != nil {
		t.Fatalf("empty scope: %d accounts, hosts kept %v", len(got), src.hosts != nil)
	}
	src.scopeTo(nil, false)
	if got, _ := src.AccountRows(t.Context()); len(got) != len(all) {
		t.Fatalf("unscoped: %d accounts", len(got))
	}
}
