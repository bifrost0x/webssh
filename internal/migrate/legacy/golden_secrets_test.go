package legacy

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGoldenSSHKeys(t *testing.T) {
	t.Parallel()
	owner := goldenUserByName(t, "local_user").ID
	store, err := golden.source.SSHKeys(owner)
	if err != nil {
		t.Fatal(err)
	}
	if len(store.Unreferenced)+len(store.Pending) != 0 {
		t.Errorf("unreferenced key files: %v, pending %v", store.Unreferenced, store.Pending)
	}
	byID := map[string]SSHKey{}
	for _, k := range store.Keys {
		byID[k.ID] = k
	}
	edge := golden.manifest.Values.EdgeCases.Keys
	if _, ok := byID[edge.Deleted]; ok {
		t.Error("deleted key is present")
	}
	if k, ok := byID[edge.Unicode128Chars]; !ok || len([]rune(k.Name)) != 128 {
		t.Errorf("key with a 128-character name: %+v", k.Name)
	}
	for _, want := range golden.manifest.Values.SSHKeys.Stored {
		t.Run(want.Label, func(t *testing.T) {
			t.Parallel()
			got, ok := byID[want.KeyID]
			if !ok {
				t.Fatal("key missing")
			}
			if got.PlaintextAtRest || got.State != KeyUsable || got.KeyType != want.KeyType || "users/user_3/keys/"+got.Filename != want.StoredFile {
				t.Fatalf("metadata %+v", got)
			}
			if !bytes.Equal(got.PEM, mustB64(t, want.PlaintextB64)) {
				t.Fatal("decrypted key differs from the manifest plaintext")
			}
			if line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(got.PublicKey))); line != want.PublicKeyOpenSSH {
				t.Fatalf("public key %s", line)
			}
		})
	}
}

func TestGoldenLegacyPlaintextKey(t *testing.T) {
	t.Parallel()
	want := golden.manifest.Values.SSHKeys.LegacyPlaintext
	store, err := golden.source.SSHKeys(goldenUserByName(t, "golden_admin").ID)
	if err != nil {
		t.Fatal(err)
	}
	keys := store.Keys
	i := slices.IndexFunc(keys, func(k SSHKey) bool { return k.ID == want.KeyID })
	if i < 0 || !keys[i].PlaintextAtRest || keys[i].KeyType != want.KeyType || keys[i].PublicKey.Type() != ssh.KeyAlgoED25519 {
		t.Fatalf("legacy plaintext key: %+v", keys)
	}
}

// The Python release refuses passphrase-protected and PKCS#8 keys on
// upload, so none is ever stored. The migration only meets stored keys;
// the vectors document how the Go parser classifies the refused formats.
func TestGoldenRejectedKeyFormats(t *testing.T) {
	t.Parallel()
	for _, v := range golden.manifest.Values.SSHKeys.Rejected {
		t.Run(v.Label, func(t *testing.T) {
			t.Parallel()
			_, err := parsePrivateKey(mustB64(t, v.PlaintextB64))
			switch {
			case v.PassphraseProtected && err == nil:
				t.Fatal("passphrase-protected key parsed without passphrase")
			case !v.PassphraseProtected && v.Format == "pkcs8" && err != nil:
				// Deviation: Go accepts unencrypted PKCS#8, Python refuses it
				// ("Unsupported or invalid private key format").
				t.Fatalf("unencrypted PKCS#8: %v", err)
			case v.PassphraseProtected && v.Format != "pkcs8" && !errors.Is(err, ErrKeyNeedsPassphrase):
				t.Fatalf("err = %v, want ErrKeyNeedsPassphrase", err)
			}
		})
	}
}

func TestGoldenHostKeys(t *testing.T) {
	t.Parallel()
	global, err := golden.source.GlobalHostKeys()
	if err != nil {
		t.Fatal(err)
	}
	wantLines := golden.manifest.Values.HostKeys.GlobalLines
	if len(global) != len(wantLines) {
		t.Fatalf("%d global entries, want %d", len(global), len(wantLines))
	}
	for i, line := range wantLines {
		marker, hosts, key, _, _, err := ssh.ParseKnownHosts([]byte(line))
		if err != nil || global[i].Marker != marker || !slices.Equal(global[i].Hosts, hosts) ||
			!bytes.Equal(global[i].Key.Marshal(), key.Marshal()) {
			t.Errorf("global entry %d: %+v", i, global[i])
		}
	}
	user, err := golden.source.UserHostKeys(goldenUserByName(t, "local_user").ID)
	if err != nil {
		t.Fatal(err)
	}
	deleted := golden.manifest.Values.EdgeCases.HostKeyDeleted.DeletedHost
	var want []string
	for _, e := range golden.manifest.Values.HostKeys.UserEntries {
		if e.Host != deleted {
			want = append(want, e.Host+" "+e.KeyType+" "+e.Fingerprint)
		}
	}
	var got []string
	for _, k := range user {
		got = append(got, strings.Join(k.Hosts, ",")+" "+k.Key.Type()+" "+k.Fingerprint)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("user host keys\n got %v\nwant %v", got, want)
	}
}

func TestGoldenNamedCredentials(t *testing.T) {
	t.Parallel()
	creds, assignments, err := golden.source.NamedCredentials(t.Context(), goldenUserByName(t, "local_user").ID)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]NamedCredential{}
	for _, c := range creds {
		byID[c.ID] = c
	}
	v := golden.manifest.Values
	for _, want := range []goldenCredential{v.NamedCredential, v.EdgeCases.NamedCredentials.UnassignedUnicode} {
		if byID[want.RecordID].Password != want.Password {
			t.Errorf("credential %s does not decrypt to the manifest password", want.RecordID)
		}
	}
	if _, ok := byID[v.EdgeCases.NamedCredentials.Deleted]; ok {
		t.Error("deleted credential present")
	}
	if a := assignments[v.NamedCredential.ResourceID]; a.CredentialID != v.NamedCredential.RecordID {
		t.Errorf("assignment %+v", a)
	}
}

func TestGoldenVault(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	owner := goldenUserByName(t, "local_user").ID
	vault, err := golden.source.Vault(owner)
	if err != nil || vault == nil || vault.Version != 2 {
		t.Fatalf("Vault = %+v, %v", vault, err)
	}
	records, err := golden.source.VaultRecords(ctx, owner, vault, golden.manifest.Values.VaultPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{}
	for _, e := range golden.manifest.Values.Vault {
		want[e.ProfileID] = e.Password
	}
	long := golden.manifest.Values.EdgeCases.VaultLongPassword
	want[long.ProfileID] = long.Password
	if len(records) != len(want) {
		t.Fatalf("%d records, want %d", len(records), len(want))
	}
	for id, password := range want {
		if records[id].Password != password {
			t.Errorf("profile %s: password differs", id)
		}
	}
	if _, err := golden.source.VaultRecords(ctx, owner, vault, "a wrong but long passphrase"); !errors.Is(err, ErrVaultPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
}
