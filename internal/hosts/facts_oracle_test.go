package hosts

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"math"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

// facts_oracle.json is recorded from app/profile_manager.py by
// testdata/facts_oracle.py.
type factsOracle struct {
	Base        []jsontext.Value  `json:"base"`
	Identities  map[string]string `json:"identities"`
	Maintenance map[string]string `json:"maintenance"`
	CheckTimes  []float64         `json:"check_times"`
	Cases       []struct {
		Name  string `json:"name"`
		Steps []struct {
			Step     []jsontext.Value  `json:"step"`
			Endpoint []jsontext.Value  `json:"endpoint"`
			Text     string            `json:"text"`
			Result   jsontext.Value    `json:"result"`
			Profiles []jsontext.Value  `json:"profiles"`
			Needed   map[string][]bool `json:"needed"`
			Reboot   map[string][]bool `json:"reboot"`
		} `json:"steps"`
	} `json:"cases"`
}

func pyTime(f float64) time.Time { return time.UnixMicro(int64(math.Round(f * 1e6))) }

func str(v jsontext.Value) string {
	s, _ := asString(v)
	return s
}

func float(t *testing.T, v jsontext.Value) float64 {
	t.Helper()
	var f float64
	if err := json.Unmarshal(v, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func loginOf(t *testing.T, e []jsontext.Value) Login {
	t.Helper()
	if len(e) != 5 {
		return Login{}
	}
	port, _ := asInt(e[1])
	return Login{Host: str(e[0]), Port: int(port), User: str(e[2]), JumpHostID: str(e[3]), SOCKSProxyID: str(e[4])}
}

func objects(t *testing.T, values []jsontext.Value) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, v := range values {
		var m map[string]any
		if err := json.Unmarshal(v, &m); err != nil {
			t.Fatal(err)
		}
		out[m["id"].(string)] = m
	}
	return out
}

func TestDetectedFactsMatchPython(t *testing.T) {
	raw, err := os.ReadFile("testdata/facts_oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var o factsOracle
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	for _, c := range o.Cases {
		t.Run(c.Name, func(t *testing.T) {
			db := storetest.Open(t, Schema())
			if err := db.Write(t.Context(), func(tx *store.Tx) error {
				_, err := Import(t.Context(), tx, oracleUser, Legacy{Profiles: o.Base}, DefaultLimits)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			s := &Service{DB: db, Limits: DefaultLimits}
			ctx := t.Context()
			for i, step := range c.Steps {
				kind, id := str(step.Step[0]), ""
				if len(step.Step) > 1 {
					id = str(step.Step[1])
				}
				ep := loginOf(t, step.Endpoint)
				var got any
				switch kind {
				case "greeting", "greeting_wrong":
					stored, changed, err := s.RecordConnectGreeting(ctx, oracleUser, id, ep, str(step.Step[2]), pyTime(float(t, step.Step[3])))
					if err != nil {
						t.Fatal(err)
					}
					got = []bool{stored != nil, changed}
				case "identity", "identity_wrong":
					identity, err := ParseIdentity(step.Text)
					if err != nil {
						t.Fatal(err)
					}
					keep := len(step.Step) > 4 && string(step.Step[4]) == "true"
					got, err = s.CacheIdentity(ctx, oracleUser, id, ep, identity, pyTime(float(t, step.Step[3])), keep)
					if err != nil {
						t.Fatal(err)
					}
				case "attempt":
					got, err = s.RecordIdentityAttempt(ctx, oracleUser, id, ep, pyTime(float(t, step.Step[2])))
					if err != nil {
						t.Fatal(err)
					}
				case "maintenance":
					m, err := ParseMaintenance(step.Text)
					if err != nil {
						t.Fatal(err)
					}
					got, err = s.CacheMaintenance(ctx, oracleUser, id, ep, m, pyTime(float(t, step.Step[3])))
					if err != nil {
						t.Fatal(err)
					}
				case "settle":
					got, err = s.SettleRebootHint(ctx, oracleUser, id, ep, step.Step[2], string(step.Step[3]) == "true")
					if err != nil {
						t.Fatal(err)
					}
				case "hints":
					var observed map[string][]jsontext.Value
					if err := json.Unmarshal(step.Step[1], &observed); err != nil {
						t.Fatal(err)
					}
					in := map[string]Greeting{}
					for pid, v := range observed {
						port, _ := asInt(v[1])
						in[pid] = Greeting{Host: str(v[0]), Port: int(port), Platform: str(v[2])}
					}
					n, err := s.CacheGreetingPlatforms(ctx, oracleUser, in)
					if err != nil {
						t.Fatal(err)
					}
					got = n
				default:
					t.Fatalf("unknown step %s", kind)
				}
				want := any(nil)
				_ = json.Unmarshal(step.Result, &want)
				gotJSON, _ := json.Marshal(got)
				var gotValue any
				_ = json.Unmarshal(gotJSON, &gotValue)
				if !reflect.DeepEqual(gotValue, want) {
					t.Errorf("step %d %s: result %v, Python %v", i, kind, gotValue, want)
				}
				profiles, err := s.Profiles(ctx, oracleUser)
				if err != nil {
					t.Fatal(err)
				}
				gotProfiles, wantProfiles := objects(t, profiles), objects(t, step.Profiles)
				for pid, w := range wantProfiles {
					if !reflect.DeepEqual(gotProfiles[pid], w) {
						a, _ := json.Marshal(gotProfiles[pid], json.Deterministic(true))
						b, _ := json.Marshal(w, json.Deterministic(true))
						t.Errorf("step %d %s, host %s:\n go     %s\n python %s", i, kind, pid, a, b)
					}
				}
				for _, p := range profiles {
					r, err := parseRecord(p)
					if err != nil {
						t.Fatal(err)
					}
					pid := r.text("id")
					for j, at := range o.CheckTimes {
						if got := identityNeeded(&r, pyTime(at)); got != step.Needed[pid][j] {
							t.Errorf("step %d, host %s, time %d: identity needed %v, Python %v", i, pid, j, got, step.Needed[pid][j])
						}
						if _, got := rebootHintNeedsCheck(&r, pyTime(at)); got != step.Reboot[pid][j] {
							t.Errorf("step %d, host %s, time %d: reboot recheck %v, Python %v", i, pid, j, got, step.Reboot[pid][j])
						}
					}
				}
			}
		})
	}
}
