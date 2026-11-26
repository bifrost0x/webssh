package keyring

import (
	"bytes"
	"errors"
	"testing"
)

func TestAADBytes(t *testing.T) {
	t.Parallel()
	a := AAD{Table: "vault_keys", Column: "private_key", Row: "7"}
	got, err := a.Bytes(SSHKey)
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte("webssh-aad-v1\x00ssh_key\x00vault_keys\x00private_key\x007"); !bytes.Equal(got, want) {
		t.Fatalf("Bytes = %q, want %q", got, want)
	}
	other, err := AAD{Table: "vault_keys", Column: "private_key", Row: "8"}.Bytes(SSHKey)
	if err != nil || bytes.Equal(got, other) {
		t.Fatal("different rows encode alike")
	}
	for name, bad := range map[string]struct {
		a AAD
		p Purpose
	}{
		"unknown purpose": {a, Purpose("other")},
		"empty row":       {AAD{Table: "t", Column: "c"}, TOTP},
		"nul":             {AAD{Table: "t\x00c", Column: "c", Row: "r"}, TOTP},
	} {
		if _, err := bad.a.Bytes(bad.p); !errors.Is(err, ErrAAD) {
			t.Errorf("%s: err %v", name, err)
		}
	}
	if len(Purposes()) != 11 || !CSRF.Known() {
		t.Error("purpose list changed")
	}
}
