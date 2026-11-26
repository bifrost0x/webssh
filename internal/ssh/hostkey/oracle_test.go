package hostkey

import (
	"encoding/base64"
	json "encoding/json/v2"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/crypto/ssh"
)

type oracleCase struct {
	Name        string            `json:"name"`
	User        *string           `json:"user"`
	Global      *string           `json:"global"`
	UserError   *string           `json:"user_error"`
	GlobalError *string           `json:"global_error"`
	UserList    []oracleListEntry `json:"user_list"`
	GlobalList  []oracleListEntry `json:"global_list"`
	Lookups     []struct {
		Hostname  string            `json:"hostname"`
		Effective [][2]string       `json:"effective"`
		Outcomes  map[string]string `json:"outcomes"`
	} `json:"lookups"`
}

type oracleListEntry struct {
	ID          string  `json:"id"`
	Host        string  `json:"host"`
	Port        *int    `json:"port"`
	Marker      *string `json:"marker"`
	Algorithm   string  `json:"algorithm"`
	Fingerprint string  `json:"fingerprint"`
	Hosts       []struct {
		Host string `json:"host"`
		Port *int   `json:"port"`
	} `json:"hosts"`
}

type oracle struct {
	Paramiko string `json:"paramiko"`
	Keys     map[string]struct {
		Type        string `json:"type"`
		Base64      string `json:"base64"`
		Fingerprint string `json:"fingerprint"`
	} `json:"keys"`
	Cases    []oracleCase `json:"cases"`
	Recorded []struct {
		Key         string `json:"key"`
		Hostname    string `json:"hostname"`
		Line        string `json:"line"`
		Fingerprint string `json:"fingerprint"`
	} `json:"recorded"`
	Base64 []struct {
		In    string  `json:"in"`
		Out   *string `json:"out"`
		Error *string `json:"error"`
	} `json:"base64"`
}

func loadOracle(t *testing.T) *oracle {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "oracle.json"))
	if err != nil {
		t.Fatalf("read oracle: %v", err)
	}
	var o oracle
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatalf("decode oracle: %v", err)
	}
	return &o
}

func TestBase64MatchesPython(t *testing.T) {
	o := loadOracle(t)
	for _, v := range o.Base64 {
		got, err := decodeBase64Lenient(v.In)
		switch {
		case v.Error != nil && err == nil:
			t.Errorf("%q: python rejected (%s), go accepted %x", v.In, *v.Error, got)
		case v.Error == nil && err != nil:
			t.Errorf("%q: python accepted, go rejected", v.In)
		case v.Error == nil && base64.StdEncoding.EncodeToString(got) != *v.Out:
			t.Errorf("%q: python %s, go %s", v.In, *v.Out, base64.StdEncoding.EncodeToString(got))
		}
	}
}

var deliberate = map[string]string{
	"revoked-falls-through/h.test/edA": "revoked",
}

func parseOptional(text *string) (*File, error) {
	if text == nil {
		return nil, nil
	}
	return Parse([]byte(*text))
}

func TestOracleCases(t *testing.T) {
	o := loadOracle(t)
	presented := map[string]ssh.PublicKey{}
	for name, k := range o.Keys {
		blob, err := base64.StdEncoding.DecodeString(k.Base64)
		if err != nil {
			t.Fatal(err)
		}
		key, err := ssh.ParsePublicKey(blob)
		if err != nil {
			t.Fatal(err)
		}
		if got := Fingerprint(key); got != k.Fingerprint {
			t.Errorf("fingerprint %s: python %s, go %s", name, k.Fingerprint, got)
		}
		presented[name] = key
	}
	for _, c := range o.Cases {
		t.Run(c.Name, func(t *testing.T) {
			user, userErr := parseOptional(c.User)
			global, globalErr := parseOptional(c.Global)
			if (c.UserError != nil) != (userErr != nil) || (c.GlobalError != nil) != (globalErr != nil) {
				t.Fatalf("parse: python user=%v global=%v, go user=%v global=%v", c.UserError, c.GlobalError, userErr, globalErr)
			}
			if userErr != nil || globalErr != nil {
				return
			}
			compareList(t, c.User, ScopeUser, "3", c.UserList)
			compareList(t, c.Global, ScopeGlobal, "", c.GlobalList)
			trust := Trust{User: user, Global: global}
			for _, l := range c.Lookups {
				var got [][2]string
				for _, k := range trust.Lookup(l.Hostname) {
					got = append(got, [2]string{k.Type, base64.StdEncoding.EncodeToString(k.Key.Marshal())})
				}
				if !slices.Equal(got, l.Effective) {
					t.Errorf("%s: effective python %v, go %v", l.Hostname, l.Effective, got)
				}
				for name, want := range l.Outcomes {
					got := trust.Verify(l.Hostname, presented[name]).String()
					// Deliberate differences, listed in the K2 report:
					// Python asked the user first and then failed with
					// "changed"; Go reports "changed" without asking.
					if want == "changed_after_prompt" {
						want = "changed"
					}
					// Python reported a revoked key as "changed" when
					// another key of its type was trusted.
					if deliberate[c.Name+"/"+l.Hostname+"/"+name] != "" {
						want = deliberate[c.Name+"/"+l.Hostname+"/"+name]
					}
					if got != want {
						t.Errorf("%s/%s: python %s, go %s", l.Hostname, name, want, got)
					}
				}
			}
		})
	}
}

func compareList(t *testing.T, text *string, scope Scope, owner string, want []oracleListEntry) {
	t.Helper()
	if text == nil {
		return
	}
	got, err := List([]byte(*text), scope, owner)
	if err != nil {
		t.Fatalf("list %s: %v", scope, err)
	}
	if len(got) != len(want) {
		t.Fatalf("list %s: python %d entries, go %d", scope, len(want), len(got))
	}
	for i, w := range want {
		g := got[i]
		marker := ""
		if w.Marker != nil {
			marker = *w.Marker
		}
		if g.ID != w.ID || g.Algorithm != w.Algorithm || g.Fingerprint != w.Fingerprint || string(g.Marker) != marker {
			t.Errorf("list %s[%d]: python %+v, go %+v", scope, i, w, g)
		}
		for j, h := range w.Hosts {
			port := 0
			if h.Port != nil {
				port = *h.Port
			}
			if g.Hosts[j].Host != h.Host || g.Hosts[j].Port != port {
				t.Errorf("list %s[%d] host %d: python %s:%d, go %+v", scope, i, j, h.Host, port, g.Hosts[j])
			}
		}
	}
}

func TestRecordedLineMatchesPython(t *testing.T) {
	o := loadOracle(t)
	for _, r := range o.Recorded {
		blob, _ := base64.StdEncoding.DecodeString(o.Keys[r.Key].Base64)
		key, err := ssh.ParsePublicKey(blob)
		if err != nil {
			t.Fatal(err)
		}
		if got := FormatLine(r.Hostname, key); got != r.Line {
			t.Errorf("line: python %q, go %q", r.Line, got)
		}
	}
}
