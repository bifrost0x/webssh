package smb

import (
	"encoding/json/jsontext"
	"slices"
	"testing"

	"github.com/bifrost0x/webssh/internal/store/storetest"
)

// TestLabMigratedDefinition is the functional check of E22: a definition
// as the Python release stored it, imported verbatim, opens the lab share
// it names with the account's password and lists it.
func TestLabMigratedDefinition(t *testing.T) {
	for _, tg := range labTargets(t) {
		if tg.windows {
			continue
		}
		t.Run(tg.name, func(t *testing.T) {
			ctx := t.Context()
			db := storetest.Open(t, Schema())
			rec := `{"name":"Lab ` + tg.share + `","host":"127.0.0.1","share":"` + tg.share + `","domain":"` + tg.domain +
				`","username":"` + tg.user + `","id":"0123456789abcdef0123456789abcdef","created_at":"2026-11-02T09:03:54.250000+00:00","updated_at":"2026-11-02T09:03:54.250000+00:00"}`
			if err := db.Write(ctx, func(tx *storeTx) error { return ImportTx(ctx, tx, 3, []jsontext.Value{jsontext.Value(rec)}) }); err != nil {
				t.Fatal(err)
			}
			f, err := (&Shares{DB: db}).Lookup(ctx, 3, "0123456789abcdef0123456789abcdef")
			if err != nil {
				t.Fatal(err)
			}
			b, err := Connect(ctx, labConfig(t, tg.port, nil), Target{Host: f.Host, Share: f.Share, Domain: f.Domain,
				Username: f.Username, Password: []byte(tg.password)})
			if err != nil {
				t.Fatalf("connect with the migrated definition: %v", err)
			}
			defer b.Close()
			dir := labDir(t, b)
			if got := names(t, b, "/"); !slices.Contains(got, dir[1:]) {
				t.Errorf("root listing %v", got)
			}
		})
	}
}
