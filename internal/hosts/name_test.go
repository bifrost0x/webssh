package hosts

import (
	"encoding/json/jsontext"
	"strings"
	"sync"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

func newHost(name string) protocol.HostsProfileSave {
	return protocol.HostsProfileSave{Name: jsonString(name), Host: v(`"unique.example"`), Username: v(`"u"`),
		AuthType: v(`"password"`)}
}

func countNamed(t *testing.T, s *Service, owner int64, name string) int {
	t.Helper()
	profiles, err := s.Profiles(t.Context(), owner)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, p := range profiles {
		r, err := parseRecord(p)
		if err != nil {
			t.Fatal(err)
		}
		if foldName(r.text("name")) == foldName(name) {
			n++
		}
	}
	return n
}

func TestProfileNameIsUniquePerUser(t *testing.T) {
	s := seeded(t, Legacy{})
	ctx := t.Context()
	if _, err := s.SaveProfile(ctx, oracleUser, newHost("Web Server")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Web Server", "web server", "  WEB SERVER  ", "WEB server"} {
		_, err := s.SaveProfile(ctx, oracleUser, newHost(name))
		if code(err) != fault.DuplicateName {
			t.Errorf("create %q: %v, want duplicate_name", name, err)
		}
	}
	// The same name with a different endpoint or authentication is still
	// a duplicate; a different name with the same endpoint is not.
	other := newHost("web server")
	other.Host, other.AuthType, other.KeyID = v(`"other.example"`), v(`"key"`), v(`"d12ad3cd-eb07-4418-8967-a3169ba3de68"`)
	if _, err := s.SaveProfile(ctx, oracleUser, other); code(err) != fault.DuplicateName {
		t.Errorf("same name, other endpoint: %v, want duplicate_name", err)
	}
	if _, err := s.SaveProfile(ctx, oracleUser, newHost("Web Server (key)")); err != nil {
		t.Errorf("same endpoint, other name refused: %v", err)
	}
	// Case folding goes beyond lower case: ß folds to ss.
	if _, err := s.SaveProfile(ctx, oracleUser, newHost("Straße")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveProfile(ctx, oracleUser, newHost("STRASSE")); code(err) != fault.DuplicateName {
		t.Errorf("casefold: %v, want duplicate_name", err)
	}
	// Another user may use the name.
	if _, err := s.SaveProfile(ctx, 4, newHost("Web Server")); err != nil {
		t.Errorf("another user's name blocks: %v", err)
	}
	if n := countNamed(t, s, oracleUser, "web server"); n != 1 {
		t.Errorf("%d hosts named web server, want 1", n)
	}
	if status := fault.DuplicateName.HTTPStatus(); status != 409 {
		t.Errorf("duplicate_name status %d, want 409", status)
	}
}

func TestProfileRenameToTakenNameIsRefused(t *testing.T) {
	s := seeded(t, Legacy{})
	ctx := t.Context()
	// "Password server" and "Key server" are golden hosts.
	rename := protocol.HostsProfileSave{ID: v(`"66d036e3-0797-4e4a-8cc5-6d20de19554a"`), Name: v(`"password SERVER"`),
		Host: v(`"key.golden.test"`), Username: v(`"k"`), AuthType: v(`"password"`)}
	if _, err := s.SaveProfile(ctx, oracleUser, rename); code(err) != fault.DuplicateName {
		t.Fatalf("rename to a taken name: %v, want duplicate_name", err)
	}
	// Changing only the case of its own name is no conflict.
	rename.Name = v(`"KEY SERVER"`)
	if _, err := s.SaveProfile(ctx, oracleUser, rename); err != nil {
		t.Fatalf("case change of the own name refused: %v", err)
	}
}

// Python stored duplicate names; the migration keeps them, and each copy
// stays editable as long as its name does not move onto another taken
// name.
func TestMigratedDuplicateNamesStayEditable(t *testing.T) {
	s := seeded(t, Legacy{Profiles: []jsontext.Value{
		v(`{"id":"dup-a","name":"Twin","host":"a.example","port":22,"username":"u","auth_type":"password"}`),
		v(`{"id":"dup-b","name":"twin ","host":"b.example","port":22,"username":"u","auth_type":"password"}`),
	}})
	ctx := t.Context()
	if n := countNamed(t, s, oracleUser, "twin"); n != 2 {
		t.Fatalf("migration kept %d of 2 duplicates", n)
	}
	edit := protocol.HostsProfileSave{ID: v(`"dup-b"`), Name: v(`"twin "`), Host: v(`"b2.example"`), Username: v(`"u"`),
		AuthType: v(`"password"`)}
	if _, err := s.SaveProfile(ctx, oracleUser, edit); err != nil {
		t.Fatalf("editing a migrated duplicate without renaming it refused: %v", err)
	}
	if _, err := s.OrganizeProfile(ctx, oracleUser, protocol.HostsProfileOrganize{ProfileID: v(`"dup-a"`), Favorite: v(`true`)}); err != nil {
		t.Fatalf("organizing a migrated duplicate refused: %v", err)
	}
	edit.Name = v(`"Password server"`)
	if _, err := s.SaveProfile(ctx, oracleUser, edit); code(err) != fault.DuplicateName {
		t.Fatalf("rename of a duplicate onto another taken name: %v, want duplicate_name", err)
	}
	edit.Name = v(`"Twin B"`)
	if _, err := s.SaveProfile(ctx, oracleUser, edit); err != nil {
		t.Fatalf("resolving the duplicate refused: %v", err)
	}
	// Once renamed away, it cannot come back onto the other copy's name.
	edit.Name = v(`"TWIN"`)
	if _, err := s.SaveProfile(ctx, oracleUser, edit); code(err) != fault.DuplicateName {
		t.Fatalf("rename back onto a taken name: %v, want duplicate_name", err)
	}
}

func TestConcurrentCreatesStoreOneHost(t *testing.T) {
	s := seeded(t, Legacy{})
	const callers = 16
	var wg sync.WaitGroup
	errs := make([]error, callers)
	for i := range callers {
		wg.Go(func() {
			_, errs[i] = s.SaveProfile(t.Context(), oracleUser, newHost("Racing host"))
		})
	}
	wg.Wait()
	created := 0
	for _, err := range errs {
		switch {
		case err == nil:
			created++
		case code(err) != fault.DuplicateName:
			t.Errorf("unexpected failure: %v", err)
		}
	}
	if created != 1 {
		t.Errorf("%d creates succeeded, want 1", created)
	}
	if n := countNamed(t, s, oracleUser, "racing host"); n != 1 {
		t.Errorf("%d hosts stored, want 1", n)
	}
}

func TestDuplicateNameMessageNamesNoOtherData(t *testing.T) {
	s := seeded(t, Legacy{})
	_, err := s.SaveProfile(t.Context(), oracleUser, newHost("Minimal"))
	fe, ok := fault.From(err)
	if !ok || fe.Code != fault.DuplicateName {
		t.Fatalf("%v, want duplicate_name", err)
	}
	if strings.Contains(fe.Message, "401cdf0a") {
		t.Errorf("message leaks the id of the other host: %q", fe.Message)
	}
}

func TestImportSkipsTakenNames(t *testing.T) {
	s := seeded(t, Legacy{Profiles: []jsontext.Value{
		v(`{"id":"padded","name":" Padded ","host":"p.example","port":22,"username":"u","auth_type":"password"}`),
	}})
	for _, name := range []string{"PASSWORD server", "padded"} {
		req := newHost(name)
		req.Host = v(`"import.example"`)
		if out := s.ImportProfile(t.Context(), oracleUser, req); !out.Duplicate {
			t.Errorf("import of %q: %+v, want a skipped duplicate", name, out)
		}
	}
}
