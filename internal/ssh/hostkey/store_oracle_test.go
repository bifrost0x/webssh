package hostkey

import (
	"encoding/base64"
	json "encoding/json/v2"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

type oracleTarget struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
	Host string `json:"host"`
	Port *int   `json:"port"`
	Keys []struct {
		Scope       string `json:"scope"`
		Algorithm   string `json:"algorithm"`
		Fingerprint string `json:"fingerprint"`
		Status      string `json:"status"`
	} `json:"keys"`
}

type storeCase struct {
	Name      string         `json:"name"`
	User      *string        `json:"user"`
	Global    *string        `json:"global"`
	Targets   []oracleTarget `json:"targets"`
	Effective []oracleTarget `json:"effective"`
	Impacts   []struct {
		ID         string         `json:"id"`
		Targets    []oracleTarget `json:"targets"`
		Unresolved bool           `json:"unresolved"`
	} `json:"impacts"`
	Deletes []struct {
		ID  string  `json:"id"`
		OK  bool    `json:"ok"`
		Raw *string `json:"raw"`
	} `json:"deletes"`
	Records []struct {
		Hostname string  `json:"hostname"`
		Key      string  `json:"key"`
		Result   string  `json:"result"`
		Raw      *string `json:"raw"`
	} `json:"records"`
}

func loadStoreCases(t *testing.T) ([]storeCase, map[string]ssh.PublicKey) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "oracle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var o struct {
		Keys map[string]struct {
			Base64 string `json:"base64"`
		} `json:"keys"`
		Stores []storeCase `json:"stores"`
	}
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	keys := map[string]ssh.PublicKey{}
	for name, k := range o.Keys {
		blob, _ := base64.StdEncoding.DecodeString(k.Base64)
		key, err := ssh.ParsePublicKey(blob)
		if err != nil {
			t.Fatal(err)
		}
		keys[name] = key
	}
	if len(o.Stores) < 5 {
		t.Fatalf("oracle has %d store cases", len(o.Stores))
	}
	return o.Stores, keys
}

const oracleUser = 3

func seededStore(t *testing.T, c storeCase) *Store {
	t.Helper()
	db := storetest.Open(t, Schema())
	err := db.Write(t.Context(), func(tx *store.Tx) error {
		if c.Global != nil {
			if err := ImportFile(t.Context(), tx, ScopeGlobal, 0, []byte(*c.Global), time.Unix(0, 0)); err != nil {
				return err
			}
		}
		if c.User != nil {
			return ImportFile(t.Context(), tx, ScopeUser, oracleUser, []byte(*c.User), time.Unix(0, 0))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return New(db, nil)
}

func toTargets(in []oracleTarget) []Target {
	out := make([]Target, len(in))
	for i, o := range in {
		out[i] = Target{ID: o.ID, Name: o.Name, Kind: o.Kind, Host: o.Host}
		if o.Port != nil {
			out[i].Port = *o.Port
		}
	}
	return out
}

func fromReports(in []TargetReport) []oracleTarget {
	out := []oracleTarget{}
	for _, r := range in {
		port := r.Port
		o := oracleTarget{ID: r.ID, Name: r.Name, Kind: r.Kind, Host: r.Host, Port: &port}
		for _, k := range r.Keys {
			o.Keys = append(o.Keys, struct {
				Scope       string `json:"scope"`
				Algorithm   string `json:"algorithm"`
				Fingerprint string `json:"fingerprint"`
				Status      string `json:"status"`
			}{string(k.Scope), k.Algorithm, k.Fingerprint, k.Status})
		}
		out = append(out, o)
	}
	return out
}

func normalize(in []oracleTarget) []oracleTarget {
	out := []oracleTarget{}
	for _, o := range in {
		if o.Port == nil {
			p := 22
			o.Port = &p
		}
		if len(o.Keys) == 0 {
			o.Keys = nil
		}
		out = append(out, o)
	}
	return out
}

func rawOf(t *testing.T, s *Store) *string {
	t.Helper()
	f, err := s.read(t.Context(), oracleUser)
	if err != nil {
		t.Fatal(err)
	}
	if !f.user.present {
		return nil
	}
	text := string(f.user.raw)
	return &text
}

// TestStoreMatchesPython replays the management views, deletions and
// recorded keys of app.host_key_store.HostKeyStore on the same files.
func TestStoreMatchesPython(t *testing.T) {
	cases, keys := loadStoreCases(t)
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			targets := toTargets(c.Targets)
			s := seededStore(t, c)
			got, err := s.Effective(t.Context(), oracleUser, targets)
			if err != nil {
				t.Fatal(err)
			}
			if g, w := normalize(fromReports(got)), normalize(c.Effective); !reflect.DeepEqual(g, w) {
				t.Errorf("effective:\n go     %+v\n python %+v", g, w)
			}
			for _, imp := range c.Impacts {
				got, err := s.DeletionImpact(t.Context(), oracleUser, imp.ID, targets)
				if err != nil {
					t.Fatalf("impact %s: %v", imp.ID, err)
				}
				if g, w := normalize(fromReports(got.Targets)), normalize(imp.Targets); !reflect.DeepEqual(g, w) || got.Unresolved != imp.Unresolved {
					t.Errorf("impact %s:\n go     %+v %v\n python %+v %v", imp.ID, g, got.Unresolved, w, imp.Unresolved)
				}
			}
			for _, d := range c.Deletes {
				s := seededStore(t, c)
				err := s.Delete(t.Context(), oracleUser, d.ID, "", false)
				if d.OK != (err == nil) || (err != nil && !fault.Is(err, fault.NotFound)) {
					t.Errorf("delete %s: python %v, go %v", d.ID, d.OK, err)
				}
				if g := rawOf(t, s); !reflect.DeepEqual(g, d.Raw) {
					t.Errorf("delete %s: file after\n go     %q\n python %q", d.ID, deref(g), deref(d.Raw))
				}
			}
			for _, r := range c.Records {
				s := seededStore(t, c)
				host, port := HostPort(r.Hostname)
				err := s.Record(t.Context(), oracleUser, host, port, keys[r.Key])
				result := "ok"
				switch {
				case fault.Is(err, fault.HostKeyChanged):
					result = "changed"
				case fault.Is(err, fault.HostKeyRevoked):
					result = "revoked"
				case err != nil:
					t.Fatalf("record %s %s: %v", r.Hostname, r.Key, err)
				}
				if result != r.Result {
					t.Errorf("record %s %s: python %s, go %s", r.Hostname, r.Key, r.Result, result)
				}
				if g := rawOf(t, s); !reflect.DeepEqual(g, r.Raw) {
					t.Errorf("record %s %s: file after\n go     %q\n python %q", r.Hostname, r.Key, deref(g), deref(r.Raw))
				}
			}
		})
	}
}

func deref(s *string) string {
	if s == nil {
		return "<no file>"
	}
	return *s
}
