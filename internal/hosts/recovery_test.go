package hosts

import (
	json "encoding/json/v2"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

type recoveryOracle struct {
	Base struct {
		Profiles     []string `json:"profiles"`
		JumpHosts    []string `json:"jump_hosts"`
		SOCKSProxies []string `json:"socks_proxies"`
	} `json:"base"`
	Summaries map[string][]RecoverySummary `json:"summaries"`
	Cases     []struct {
		Name     string `json:"name"`
		Kind     string `json:"kind"`
		Selector string `json:"selector"`
		Result   struct {
			OK    bool    `json:"ok"`
			Error *string `json:"error"`
		} `json:"result"`
		After struct {
			Profiles     []string `json:"profiles"`
			JumpHosts    []string `json:"jump_hosts"`
			SOCKSProxies []string `json:"socks_proxies"`
		} `json:"after"`
	} `json:"cases"`
	Final map[string][]RecoverySummary `json:"final_summaries"`
}

var testRecoveryLimits = RecoveryLimits{MaxBytes: 16 << 20, MaxRecords: 10_000}

func readRecoveryOracle(t *testing.T) recoveryOracle {
	t.Helper()
	raw, err := os.ReadFile("testdata/recovery_oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var o recoveryOracle
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	return o
}

func recoveryService(t *testing.T, o recoveryOracle) *Service {
	t.Helper()
	db := storetest.Open(t, Schema())
	legacy := Legacy{Profiles: values(o.Base.Profiles), JumpHosts: values(o.Base.JumpHosts), SOCKSProxies: values(o.Base.SOCKSProxies)}
	if err := db.Write(t.Context(), func(tx *store.Tx) error {
		_, err := Import(t.Context(), tx, oracleUser, legacy, DefaultLimits)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return &Service{DB: db, Limits: DefaultLimits}
}

// The summaries, the selectors and every deletion outcome equal the Python
// release's on the same stores (testdata/recovery_oracle.py).
func TestRecoveryMatchesPython(t *testing.T) {
	o := readRecoveryOracle(t)
	s := recoveryService(t, o)
	summaries := func() map[string][]RecoverySummary {
		out := map[string][]RecoverySummary{}
		for _, k := range RecoveryKinds() {
			got, err := s.RecoverySummaries(t.Context(), oracleUser, k, testRecoveryLimits)
			if err != nil {
				t.Fatal(err)
			}
			out[string(k)] = got
		}
		return out
	}
	if got := summaries(); !reflect.DeepEqual(got, o.Summaries) {
		t.Fatalf("summaries:\n got %v\nwant %v", got, o.Summaries)
	}
	for _, c := range o.Cases {
		err := s.DeleteRecovery(t.Context(), oracleUser, RecoveryKind(c.Kind), c.Selector, testRecoveryLimits)
		switch {
		case c.Result.OK && err != nil:
			t.Fatalf("%s: %v", c.Name, err)
		case !c.Result.OK:
			fe, ok := fault.From(err)
			if !ok || c.Result.Error == nil || fe.Message != *c.Result.Error {
				t.Fatalf("%s: got %v, want %v", c.Name, err, *c.Result.Error)
			}
		}
		got := exported(t, s)
		if !sameRecords(t, got.Profiles, c.After.Profiles) || !sameRecords(t, got.JumpHosts, c.After.JumpHosts) ||
			!sameRecords(t, got.SOCKSProxies, c.After.SOCKSProxies) {
			t.Fatalf("%s: stores after:\n got %v\nwant %+v", c.Name, got, c.After)
		}
	}
	if got := summaries(); !reflect.DeepEqual(got, o.Final) {
		t.Fatalf("final summaries:\n got %v\nwant %v", got, o.Final)
	}
}

// sameRecords compares two lists of JSON objects member by member,
// whatever their white space and escaping.
func sameRecords(t *testing.T, a, b []string) bool {
	t.Helper()
	norm := func(in []string) []string {
		out := make([]string, len(in))
		for i, s := range in {
			r, err := parseRecord([]byte(s))
			if err != nil {
				t.Fatal(err)
			}
			out[i] = string(flaskJSON(r.encode()))
		}
		return out
	}
	return slices.Equal(norm(a), norm(b))
}

func TestRecoveryLimits(t *testing.T) {
	o := readRecoveryOracle(t)
	s := recoveryService(t, o)
	_, err := s.RecoverySummaries(t.Context(), oracleUser, RecoverProfiles, RecoveryLimits{MaxBytes: 16 << 20, MaxRecords: 2})
	if fe, ok := fault.From(err); !ok || fe.Message != "Connection storage quota exceeded: more than 2 recovery records are not allowed" {
		t.Fatalf("record ceiling: %v", err)
	}
	_, err = s.RecoverySummaries(t.Context(), oracleUser, RecoverJumpHosts, RecoveryLimits{MaxBytes: 100, MaxRecords: 100})
	if fe, ok := fault.From(err); !ok || fe.Message != "Connection storage quota exceeded: stored data exceeds its recovery byte limit" {
		t.Fatalf("byte ceiling: %v", err)
	}
	// A deletion reads the profiles within the ceilings as well.
	sel := o.Summaries["jump-hosts"][1].Selector
	err = s.DeleteRecovery(t.Context(), oracleUser, RecoverJumpHosts, sel, RecoveryLimits{MaxBytes: 16 << 20, MaxRecords: 2})
	if fe, ok := fault.From(err); !ok || !strings.Contains(fe.Message, "recovery records") {
		t.Fatalf("delete beyond the ceiling: %v", err)
	}
	if _, err := s.RecoverySummaries(t.Context(), oracleUser, "keys", testRecoveryLimits); !fault.Is(err, fault.InvalidValue) {
		t.Fatalf("unknown kind: %v", err)
	}
	if err := s.DeleteRecovery(t.Context(), oracleUser, "keys", sel, testRecoveryLimits); !fault.Is(err, fault.InvalidValue) {
		t.Fatalf("unknown kind: %v", err)
	}
	// Another user's selector names nothing for this user.
	if err := s.DeleteRecovery(t.Context(), oracleUser+1, RecoverJumpHosts, sel, testRecoveryLimits); !fault.Is(err, fault.NotFound) {
		t.Fatalf("other user: %v", err)
	}
}

func FuzzRecoverySelector(f *testing.F) {
	f.Add("r1:0:" + strings.Repeat("0", 64))
	f.Add("r1:9999999999:" + strings.Repeat("a", 64))
	f.Add("r1:-1:x")
	r, err := parseRecord([]byte(`{"id":"a","name":"b"}`))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(recoverySelector("profiles:1", 0, r))
	f.Fuzz(func(t *testing.T, sel string) {
		i := resolveRecoverySelector("profiles:1", []record{r}, sel)
		if i >= 0 && sel != recoverySelector("profiles:1", 0, r) {
			t.Fatalf("selector %q resolved to %d", sel, i)
		}
	})
}
