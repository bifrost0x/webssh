package legacy

import (
	"testing"
)

// A repeated member name keeps its last value, as in a Python dict, and
// the store is flagged (condition C6: duplicate names like Python).
func TestDecodeStoreDuplicateNames(t *testing.T) {
	t.Parallel()
	doc, err := decodeStore([]byte(`{"schema_version":2,"theme":"dark","theme":"light","x":1}`), userStores[5])
	if err != nil {
		t.Fatal(err)
	}
	if !doc.DuplicateNames || doc.Object["theme"] != "light" || string(doc.Raw) != `{"schema_version":2,"theme":"light","x":1}` {
		t.Fatalf("%+v %s", doc, doc.Raw)
	}
	keys := []byte(`{"schema_version":2,"keys":[{"id":"a","name":"one","name":"two","filename":"a.pem"}]}`)
	doc, err = decodeStore(keys, keysStore)
	if err != nil || !doc.DuplicateNames {
		t.Fatalf("%+v, %v", doc, err)
	}
}

// Lifting keeps the member order Python's dict has: startup_mode is
// appended, tailscale_authorized removed, schema_version set in place.
func TestDecodeStoreLiftsRawInOrder(t *testing.T) {
	t.Parallel()
	in := `{"profiles":[{"id":"a","tailscale_authorized":true,"command_id":"c","port":22},{"id":"b","startup_mode":"none"}]}`
	doc, err := decodeStore([]byte(in), userStores[0])
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
	doc, err = decodeStore([]byte(`{"schema_version":1,"theme":"x"}`), userStores[5])
	if err != nil || string(doc.Raw) != `{"schema_version":2,"theme":"x"}` {
		t.Fatalf("settings v1: %s %v", doc.Raw, err)
	}
	doc, err = decodeStore([]byte(`{"schema_version":2,"commands":[{"id":"x"}]}`), storeSpec{name: "commands", topList: true})
	if err != nil || string(doc.Raw) != `[{"id":"x"}]` || len(doc.Items) != 1 {
		t.Fatalf("commands object form: %s %v", doc.Raw, err)
	}
	if _, err := (Document{Store: "x", Raw: []byte(`{"l":1}`)}).RawList("l"); err == nil {
		t.Fatal("a number is not a list")
	}
}
