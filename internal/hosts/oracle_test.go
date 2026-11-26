package hosts

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"fmt"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/realtime/protocol/protocoltest"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

// The oracle is recorded from the Python stores by testdata/oracle.py.

type oracleStores struct {
	Profiles     []string `json:"profiles"`
	JumpHosts    []string `json:"jump_hosts"`
	SOCKSProxies []string `json:"socks_proxies"`
}

type oracleCase struct {
	Name    string                    `json:"name"`
	Type    string                    `json:"type"`
	Payload string                    `json:"payload"`
	OK      *string                   `json:"ok"`
	Error   *string                   `json:"error"`
	Details *string                   `json:"details"`
	Code    *string                   `json:"code"`
	After   map[string]jsontext.Value `json:"after"`
}

type oracleCorpus struct {
	Now       string              `json:"now"`
	Base      oracleStores        `json:"base"`
	BaseRaw   map[string][]string `json:"base_raw"`
	FileSizes map[string]int      `json:"base_file_sizes"`
	Keys      []string            `json:"keys"`
	Sets      []string            `json:"command_sets"`
	Cases     []oracleCase        `json:"cases"`
	Presets   []struct {
		Value string `json:"value"`
		Valid bool   `json:"valid"`
	} `json:"presets"`
}

func readOracle(t *testing.T) oracleCorpus {
	t.Helper()
	raw, err := os.ReadFile("testdata/oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var c oracleCorpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func values(items []string) []jsontext.Value {
	out := make([]jsontext.Value, len(items))
	for i, s := range items {
		out[i] = jsontext.Value(s)
	}
	return out
}

func strs(items []jsontext.Value) []string {
	out := make([]string, len(items))
	for i, v := range items {
		out[i] = string(v)
	}
	return out
}

type fakeKeys map[string]bool

func (k fakeKeys) HasKey(_ context.Context, _ int64, keyID string) (bool, error) {
	return k[keyID], nil
}

const oracleUser = 3

func oracleService(t *testing.T, c oracleCorpus) *Service {
	t.Helper()
	db := storetest.Open(t, Schema())
	legacy := Legacy{Profiles: values(c.Base.Profiles), JumpHosts: values(c.Base.JumpHosts), SOCKSProxies: values(c.Base.SOCKSProxies)}
	err := db.Write(t.Context(), func(tx *store.Tx) error {
		_, err := Import(t.Context(), tx, oracleUser, legacy, DefaultLimits)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse("2006-01-02T15:04:05.999999-07:00", c.Now)
	if err != nil {
		t.Fatal(err)
	}
	keys := fakeKeys{}
	for _, k := range c.Keys {
		keys[k] = true
	}
	n := 0
	return &Service{
		DB: db, Keys: keys, Limits: DefaultLimits,
		Now: func() time.Time { return now },
		NewID: func() string {
			n++
			return fmt.Sprintf("00000000-0000-4000-8000-%012d", n)
		},
	}
}

func exported(t *testing.T, s *Service) oracleStores {
	t.Helper()
	var out oracleStores
	err := s.DB.Read(t.Context(), func(tx *store.Tx) error {
		l, err := Export(t.Context(), tx, oracleUser)
		out = oracleStores{strs(l.Profiles), strs(l.JumpHosts), strs(l.SOCKSProxies)}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestOracleBaseIsStoredByteForByte(t *testing.T) {
	c := readOracle(t)
	s := oracleService(t, c)
	got := exported(t, s)
	if !slices.Equal(got.Profiles, c.Base.Profiles) || !slices.Equal(got.JumpHosts, c.Base.JumpHosts) ||
		!slices.Equal(got.SOCKSProxies, c.Base.SOCKSProxies) {
		t.Fatalf("stores differ after import:\n got %v\nwant %v", got, c.Base)
	}
	// The list the page gets is the stored JSON of every host.
	listed, err := s.Profiles(t.Context(), oracleUser)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(strs(listed), c.Base.Profiles) {
		t.Fatalf("listed profiles differ:\n got %v\nwant %v", strs(listed), c.Base.Profiles)
	}
}

func TestOracleImportDropsInvalidFactsLikePython(t *testing.T) {
	c := readOracle(t)
	db := storetest.Open(t, Schema())
	var report ImportReport
	err := db.Write(t.Context(), func(tx *store.Tx) error {
		var err error
		report, err = Import(t.Context(), tx, oracleUser, Legacy{
			Profiles:     values(c.BaseRaw["profiles.json"]),
			JumpHosts:    values(c.BaseRaw["jump_hosts.json"]),
			SOCKSProxies: values(c.BaseRaw["socks_proxies.json"]),
		}, DefaultLimits)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.DroppedFacts != 1 {
		t.Errorf("dropped %d facts, want 1 (detected_virt)", report.DroppedFacts)
	}
	got := exported(t, &Service{DB: db})
	if !slices.Equal(got.Profiles, c.Base.Profiles) {
		t.Fatalf("profiles after dropping facts differ:\n got %v\nwant %v", got.Profiles, c.Base.Profiles)
	}
}

func TestOracleDocumentSizesMatchPythonFiles(t *testing.T) {
	c := readOracle(t)
	for name, k := range map[string]kind{"profiles.json": profileKind, "jump_hosts.json": jumpKind, "socks_proxies.json": socksKind} {
		records, err := importRecords(values(c.BaseRaw[name]), name, func(*record) bool { return true })
		if err != nil {
			t.Fatal(err)
		}
		if got := documentSize(k, records, true); got != c.FileSizes[name] {
			t.Errorf("%s: size %d, Python wrote %d bytes", name, got, c.FileSizes[name])
		}
	}
}

func TestOracleCases(t *testing.T) {
	c := readOracle(t)
	for _, tc := range c.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			s := oracleService(t, c)
			routes := map[string]protocol.Route{}
			for _, r := range s.Routes() {
				routes[r.Type] = r
			}
			peer := protocoltest.NewPeer(t, principal.Principal{UserID: oracleUser, SessionID: "s", Username: "golden"})
			got, werr := protocoltest.Call(t.Context(), routes[tc.Type], peer, jsontext.Value(tc.Payload))
			switch {
			case tc.OK != nil:
				if werr != nil {
					t.Fatalf("error %s %q, Python succeeded with %s", werr.Code, werr.Message, *tc.OK)
				}
				if string(got) != *tc.OK {
					t.Fatalf("result differs:\n got %s\nwant %s", got, *tc.OK)
				}
			default:
				if werr == nil {
					t.Fatalf("succeeded with %s, Python failed with %q", got, *tc.Error)
				}
				if *tc.Error != "confirmation" && werr.Message != *tc.Error {
					t.Fatalf("message %q (%s), Python %q", werr.Message, werr.Code, *tc.Error)
				}
				if tc.Code != nil && string(werr.Code) != *tc.Code {
					t.Fatalf("code %s, Python %s", werr.Code, *tc.Code)
				}
				checkDetails(t, werr.Details, tc.Details)
			}
			after := exported(t, s)
			want := c.Base
			for key, v := range tc.After {
				var list []string
				if err := json.Unmarshal(v, &list); err != nil {
					t.Fatal(err)
				}
				switch key {
				case "profiles":
					want.Profiles = list
				case "jump_hosts":
					want.JumpHosts = list
				default:
					want.SOCKSProxies = list
				}
			}
			for _, pair := range [][2][]string{{after.Profiles, want.Profiles}, {after.JumpHosts, want.JumpHosts}, {after.SOCKSProxies, want.SOCKSProxies}} {
				if !slices.Equal(pair[0], pair[1]) {
					t.Fatalf("stored records differ:\n got %v\nwant %v", pair[0], pair[1])
				}
			}
		})
	}
}

func checkDetails(t *testing.T, got map[string]any, want *string) {
	t.Helper()
	if want == nil {
		if len(got) != 0 {
			t.Fatalf("details %v, Python sent none", got)
		}
		return
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var a, b any
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(*want), &b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("details differ:\n got %s\nwant %s", raw, *want)
	}
}
