package legacy

import (
	"testing"
)

// A repeated member name keeps its last value, as in a Python dict, and
// the store is flagged (condition C6: duplicate names like Python).
func TestDecodeStoreDuplicateNames(t *testing.T) {
	t.Parallel()
	doc, err := decodeStoreValues([]byte(`{"schema_version":2,"theme":"dark","theme":"light","x":1}`), userStores[5])
	if err != nil {
		t.Fatal(err)
	}
	if !doc.DuplicateNames || doc.Object["theme"] != "light" || string(doc.Raw) != `{"schema_version":2,"theme":"light","x":1}` {
		t.Fatalf("%+v %s", doc, doc.Raw)
	}
	keys := []byte(`{"schema_version":2,"keys":[{"id":"a","name":"one","name":"two","filename":"a.pem"}]}`)
	doc, err = decodeStoreValues(keys, keysStore)
	if err != nil || !doc.DuplicateNames {
		t.Fatalf("%+v, %v", doc, err)
	}
}

// Lifting keeps the member order Python's dict has: startup_mode is
// appended, tailscale_authorized removed, schema_version set in place.
func TestDecodeStoreLiftsRawInOrder(t *testing.T) {
	t.Parallel()
	in := `{"profiles":[{"id":"a","tailscale_authorized":true,"command_id":"c","port":22},{"id":"b","startup_mode":"none"}]}`
	doc, err := decodeStoreValues([]byte(in), userStores[0])
	if err != nil {
		t.Fatal(err)
	}
	want := `{"profiles":[{"id":"a","command_id":"c","port":22,"startup_mode":"command"},{"id":"b","startup_mode":"none"}],"schema_version":3}`
	if string(doc.Raw) != want || !doc.Lifted || doc.Version != 0 {
		t.Fatalf("%s", doc.Raw)
	}
	items, err := doc.RawList("profiles")
	if err != nil || len(items) != 2 || string(items[1]) != `{"id":"b","startup_mode":"none"}` {
		t.Fatalf("%v %v", items, err)
	}
	doc, err = decodeStoreValues([]byte(`{"schema_version":1,"theme":"x"}`), userStores[5])
	if err != nil || string(doc.Raw) != `{"schema_version":2,"theme":"x"}` {
		t.Fatalf("settings v1: %s %v", doc.Raw, err)
	}
	doc, err = decodeStoreValues([]byte(`{"schema_version":2,"commands":[{"id":"x"}]}`), storeSpec{name: "commands", topList: true})
	if err != nil || string(doc.Raw) != `[{"id":"x"}]` || len(doc.Items) != 1 {
		t.Fatalf("commands object form: %s %v", doc.Raw, err)
	}
	if _, err := (Document{Store: "x", Raw: []byte(`{"l":1}`)}).RawList("l"); err == nil {
		t.Fatal("a number is not a list")
	}
}

// decodeStoreValues is decodeStore with the generic values, as the
// public readers return it.
func decodeStoreValues(data []byte, spec storeSpec) (Document, error) {
	doc, err := decodeStore(data, spec)
	if err != nil {
		return Document{}, err
	}
	return doc.withValues(spec)
}

// The steps read Raw only: decodeStore leaves the generic values out,
// which cost several times the file size for a large store (R2 L-2),
// and the record count comes from Raw.
func TestDecodeStoreKeepsRawOnly(t *testing.T) {
	t.Parallel()
	doc, err := decodeStore([]byte(`{"schema_version":3,"profiles":[{"id":"a"},{"id":"b"},{"id":"c"}]}`), userStores[0])
	if err != nil {
		t.Fatal(err)
	}
	if doc.Object != nil || doc.Items != nil || doc.Entries != nil {
		t.Fatalf("generic values decoded: %+v", doc)
	}
	if n := doc.records("profiles"); n != 3 {
		t.Fatalf("records %d, want 3", n)
	}
	ctx, err := decodeStore([]byte(`{"version":1,"hosts":{"a":{},"b":{}}}`), userStores[8])
	if err != nil || ctx.records("hosts") != 2 {
		t.Fatalf("map store: %d %v", ctx.records("hosts"), err)
	}
	cmds, err := decodeStore([]byte(`[{"id":"x"},{"id":"y"}]`), storeSpec{name: "commands", topList: true})
	if err != nil || cmds.records("") != 2 {
		t.Fatalf("commands: %d %v", cmds.records(""), err)
	}
	if _, err := decodeStore([]byte(`{"schema_version":3,"profiles":7}`), userStores[0]); err == nil {
		t.Fatal("a number under the list key accepted")
	}
	if doc, err := decodeStore([]byte(`{"schema_version":3,"profiles":null}`), userStores[0]); err != nil || doc.records("profiles") != 0 {
		t.Fatalf("null list: %v", err)
	}
}

// E19 and the entities written with it read the host stores once per
// source and share the records; each step keeping a copy held the
// profile store five times (R2 L-2). Each step still gets its own slice.
func TestUserHostsAreReadOnce(t *testing.T) {
	dir := copyGolden(t)
	src, err := Open(t.Context(), dir, golden.manifest.SecretKey.Value)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	first, err := readUserHosts(t.Context(), src)
	if err != nil {
		t.Fatal(err)
	}
	second, err := readUserHosts(t.Context(), src)
	if err != nil {
		t.Fatal(err)
	}
	shared := false
	for i := range first {
		if p, q := first[i].legacy.Profiles, second[i].legacy.Profiles; len(p) > 0 {
			if &p[0][0] != &q[0][0] {
				t.Fatalf("user %d: profiles read twice", first[i].id)
			}
			shared = true
		}
	}
	if !shared {
		t.Fatal("golden has no saved hosts")
	}
	first[0].result.DroppedFacts = 7
	if second[0].result.DroppedFacts != 0 {
		t.Fatal("steps share their import result")
	}
}
