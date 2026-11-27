package vault

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"maps"
	"os"
	"slices"
	"testing"

	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/store"
)

// The oracle is recorded from the Python rules by
// testdata/credential_oracle.py.
type credentialOracle struct {
	User        int64  `json:"user"`
	Incarnation string `json:"incarnation"`
	Passphrase  string `json:"passphrase"`
	Normalize   []struct {
		Target jsontext.Value `json:"target"`
		OK     jsontext.Value `json:"ok"`
		Error  string         `json:"error"`
	} `json:"normalize"`
	Records struct {
		Profiles     []jsontext.Value `json:"profiles"`
		JumpHosts    []jsontext.Value `json:"jump_hosts"`
		SOCKSProxies []jsontext.Value `json:"socks_proxies"`
		SMBShares    []jsontext.Value `json:"smb_shares"`
	} `json:"records"`
	Resources []struct {
		ID          string `json:"id"`
		Kind        string `json:"kind"`
		Fingerprint string `json:"fingerprint"`
	} `json:"resources"`
	Assignments map[string]struct {
		CredentialID string `json:"credential_id"`
		Fingerprint  string `json:"fingerprint"`
		Generation   string `json:"generation"`
	} `json:"assignments"`
	Statuses map[string]string `json:"statuses"`
	Prepares []struct {
		Mutation jsontext.Value `json:"mutation"`
		Error    string         `json:"error"`
	} `json:"prepares"`
	Binds []struct {
		Method string         `json:"method"`
		Data   jsontext.Value `json:"data"`
		OK     bool           `json:"ok"`
	} `json:"binds"`
	Vaults []struct {
		Version  int    `json:"version"`
		Document string `json:"document"`
		Records  map[string]struct {
			Fingerprint string `json:"fingerprint"`
			Password    string `json:"password"`
		} `json:"records"`
		Revision string `json:"revision"`
		Wrong    struct {
			Error string `json:"error"`
		} `json:"wrong"`
	} `json:"vaults"`
	Short struct {
		Error string `json:"error"`
	} `json:"short_passphrase"`
}

func readCredentialOracle(t *testing.T) credentialOracle {
	t.Helper()
	raw, err := os.ReadFile("testdata/credential-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var o credentialOracle
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	return o
}

func (o credentialOracle) records() Records {
	return Records{Profiles: o.Records.Profiles, JumpHosts: o.Records.JumpHosts, SOCKSProxies: o.Records.SOCKSProxies,
		SMBShares: o.Records.SMBShares, SMB: true}
}

func TestNormalizeTargetMatchesPython(t *testing.T) {
	t.Parallel()
	for i, c := range readCredentialOracle(t).Normalize {
		got, err := normalizeTarget(c.Target)
		if c.Error != "" {
			if string(codeOf(err)) != c.Error {
				t.Errorf("case %d %s: error %v, want %s", i, c.Target, err, c.Error)
			}
			continue
		}
		want, _ := canonical(c.OK)
		if err != nil || got != want {
			t.Errorf("case %d %s:\n got %s %v\nwant %s", i, c.Target, got, err, want)
		}
	}
}

func TestResourcesMatchPython(t *testing.T) {
	t.Parallel()
	o := readCredentialOracle(t)
	got := ResourcesFromRecords(o.records())
	if len(got) != len(o.Resources) {
		t.Fatalf("%d resources, want %d", len(got), len(o.Resources))
	}
	for i, want := range o.Resources {
		g := got[i]
		if g.ID != want.ID || string(g.Kind) != want.Kind || g.Fingerprint != want.Fingerprint {
			t.Errorf("resource %d = %s %s %s, want %+v", i, g.ID, g.Kind, g.Fingerprint, want)
		}
	}
}

func oracleDoc(o credentialOracle) *credDoc {
	d := &credDoc{creds: []credRow{{ID: "c1", Name: "One"}, {ID: "c2", Name: "Two"}}}
	for _, id := range slices.Sorted(maps.Keys(o.Assignments)) {
		a := o.Assignments[id]
		d.assigns = append(d.assigns, Assignment{ResourceID: id, CredentialID: a.CredentialID, Fingerprint: a.Fingerprint, Generation: a.Generation})
	}
	return d
}

func TestStatusMatchesPython(t *testing.T) {
	t.Parallel()
	o := readCredentialOracle(t)
	d := oracleDoc(o)
	all := ResourcesFromRecords(o.records())
	for id, want := range o.Statuses {
		r, err := resolve(all, id)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if got := status(true, d, r); string(got) != want {
			t.Errorf("%s: status %s, want %s", id, got, want)
		}
	}
	if got := status(false, d, all[0]); got != StatusDisabled {
		t.Errorf("disabled: %s", got)
	}
}

func TestPrepareMatchesPython(t *testing.T) {
	t.Parallel()
	o := readCredentialOracle(t)
	r := newCredRig(t)
	r.stores.set(o.User, o.records())
	err := r.db.Write(t.Context(), func(tx *store.Tx) error {
		for _, id := range []string{"c1", "c2"} {
			if err := ImportCredentialTx(t.Context(), tx, r.ring, ImportedCredential{UserID: o.User, ID: id, Name: id,
				Version: "v", UpdatedAt: "x", Password: []byte("secret")}); err != nil {
				return err
			}
		}
		var keep []Assignment
		for _, a := range oracleDoc(o).assigns {
			if a.CredentialID != "gone" {
				keep = append(keep, a)
			}
		}
		return ImportAssignmentsTx(t.Context(), tx, o.User, keep, nil)
	})
	if err != nil {
		t.Fatal(err)
	}
	p := principaltest.User(o.User)
	for i, c := range o.Prepares {
		body := pyjson.Object([]pyjson.Member{{Name: "operation", Value: pyjson.String("native")}, {Name: "mutation", Value: c.Mutation}})
		if c.Mutation == nil {
			body = jsontext.Value(`{"operation":"native","mutation":[]}`)
		}
		_, err := r.svc.Prepare(as(p), body)
		if string(codeOf(err)) != c.Error {
			t.Errorf("case %d %s: %v, want %q", i, c.Mutation, err, c.Error)
		}
	}
}

func TestBindsSavedSecretMatchesPython(t *testing.T) {
	t.Parallel()
	for _, c := range readCredentialOracle(t).Binds {
		if got := bindsSavedSecret(c.Method, c.Data); got != c.OK {
			t.Errorf("%s %s: %v, want %v", c.Method, c.Data, got, c.OK)
		}
	}
}

func TestLegacyVaultMatchesPython(t *testing.T) {
	t.Parallel()
	o := readCredentialOracle(t)
	if len(o.Vaults) != 2 {
		t.Fatalf("%d vaults", len(o.Vaults))
	}
	for _, v := range o.Vaults {
		env, err := parseLegacyVault([]byte(v.Document))
		if err != nil || env.version != v.Version {
			t.Fatalf("v%d: parse %v", v.Version, err)
		}
		recs, err := openLegacyVault(env, o.User, o.Incarnation, o.Passphrase)
		if err != nil || len(recs) != len(v.Records) {
			t.Fatalf("v%d: open %d records, %v", v.Version, len(recs), err)
		}
		for _, rec := range recs {
			want := v.Records[rec.ResourceID]
			if rec.Password != want.Password || rec.Fingerprint != want.Fingerprint {
				t.Errorf("v%d %s differs", v.Version, rec.ResourceID)
			}
		}
		if _, err := openLegacyVault(env, o.User, o.Incarnation, "another long passphrase"); string(codeOf(err)) != v.Wrong.Error {
			t.Errorf("v%d wrong passphrase: %v", v.Version, err)
		}
		if _, err := openLegacyVault(env, o.User, "2026-11-20T08:15:30", o.Passphrase); string(codeOf(err)) != "vault_unlock_failed" {
			t.Errorf("v%d other incarnation: %v", v.Version, err)
		}
		rev, ok := legacyRevision(legacyVault{Document: []byte(v.Document)})
		if !ok || rev != v.Revision {
			t.Errorf("v%d revision %s, want %s", v.Version, rev, v.Revision)
		}
	}
	env, _ := parseLegacyVault([]byte(o.Vaults[0].Document))
	if _, err := openLegacyVault(env, o.User, o.Incarnation, "too short"); string(codeOf(err)) != o.Short.Error {
		t.Errorf("short passphrase: %v", err)
	}
}
