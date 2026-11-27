package vault

import (
	"encoding/json/jsontext"
	"testing"
)

func FuzzParseLegacyVault(f *testing.F) {
	f.Add([]byte(`{"version":2,"kdf":"scrypt-131072-8-1","salt":"AAAAAAAAAAAAAAAAAAAAAA==","nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AA=="}`))
	f.Add([]byte(`{"version":1}`))
	f.Fuzz(func(t *testing.T, doc []byte) {
		e, err := parseLegacyVault(doc)
		if err == nil && (len(e.nonce) != 12 || (e.version != 1 && e.version != 2)) {
			t.Fatalf("accepted %q", doc)
		}
	})
}

func FuzzParseLegacyRecords(f *testing.F) {
	f.Add([]byte(`{"p1":{"fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","password":"x"}}`), 1)
	f.Add([]byte(`{"p1":{"fingerprint":"a","password":"x","generation":"b"}}`), 2)
	f.Fuzz(func(t *testing.T, plain []byte, version int) {
		recs, err := parseLegacyRecords(plain, version)
		if err != nil {
			return
		}
		for _, r := range recs {
			if r.Password == "" || len(r.Password) > MaxSecretBytes {
				t.Fatalf("accepted record %+v", r)
			}
		}
	})
}

func FuzzNormalizeTarget(f *testing.F) {
	f.Add([]byte(`{"host":"a","username":"u","proxy_jump":{"jump_host_id":"j"}}`))
	f.Add([]byte(`{"kind":"socks","remote_dns":false}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		v := jsontext.Value(raw)
		if !v.IsValid() {
			return
		}
		a, errA := normalizeTarget(v)
		b, errB := normalizeTarget(v)
		if (errA == nil) != (errB == nil) || a != b {
			t.Fatal("not deterministic")
		}
	})
}

func FuzzResourcesFromRecords(f *testing.F) {
	f.Add([]byte(`{"id":"p","host":"h","port":22,"jump_host_id":"j"}`), []byte(`{"id":"j","host":"b"}`))
	f.Fuzz(func(t *testing.T, profile, jump []byte) {
		p, j := jsontext.Value(profile), jsontext.Value(jump)
		if !p.IsValid() || !j.IsValid() {
			return
		}
		for _, r := range ResourcesFromRecords(Records{Profiles: []jsontext.Value{p}, JumpHosts: []jsontext.Value{j}}) {
			if r.ID == "" {
				t.Fatal("resource without id")
			}
		}
	})
}
