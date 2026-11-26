package keyring

import (
	"bytes"
	"errors"
	"testing"
)

// FuzzOpen feeds arbitrary bytes and records to Ring.Open: it never panics,
// returns either the plaintext of a genuine value or one of the documented
// errors, and never returns plaintext together with an error.
func FuzzOpen(f *testing.F) {
	r := katRing(f)
	// The frozen known-answer value is the one genuine input; a value
	// sealed here would differ in every fuzzing worker.
	sealed := unhex(f, katSealed)
	f.Add(sealed, "vault_keys", "private_key", "7")
	f.Add([]byte{}, "t", "c", "r")
	f.Add([]byte{1}, "t", "c", "r")
	f.Add(bytes.Repeat([]byte{1}, MinSealedSize), "t", "c\x00", "r")
	f.Fuzz(func(t *testing.T, in []byte, table, column, row string) {
		ad := AAD{Table: table, Column: column, Row: row}
		plain, err := r.Open(SSHKey, ad, in)
		if err != nil {
			if plain != nil {
				t.Fatal("plaintext with an error")
			}
			for _, known := range []error{ErrFormat, ErrWrongKey, ErrDecrypt, ErrAAD} {
				if errors.Is(err, known) {
					return
				}
			}
			t.Fatalf("undocumented error %v", err)
		}
		// Only the genuine seed opens.
		if !bytes.Equal(in, sealed) || ad != katAAD || string(plain) != "kat plaintext" {
			t.Fatalf("forged value opened: %x for %+v", in, ad)
		}
	})
}

// FuzzSealRoundTrip checks that every plaintext and record round-trips and
// that the value opens for no other row.
func FuzzSealRoundTrip(f *testing.F) {
	r := katRing(f)
	f.Add([]byte("plain"), "vault_keys", "private_key", "7")
	f.Add([]byte{}, "a", "b", "c")
	f.Fuzz(func(t *testing.T, plain []byte, table, column, row string) {
		ad := AAD{Table: table, Column: column, Row: row}
		sealed, err := r.Seal(TOTP, ad, plain)
		if err != nil {
			if !errors.Is(err, ErrAAD) {
				t.Fatalf("Seal: %v", err)
			}
			return
		}
		got, err := r.Open(TOTP, ad, sealed)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("round trip: %q, %v", got, err)
		}
		moved := ad
		moved.Row += "0"
		if _, err := r.Open(TOTP, moved, sealed); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("opened for another row: %v", err)
		}
	})
}

// FuzzAADBytes checks that the encoding is injective: two different valid
// records never encode alike.
func FuzzAADBytes(f *testing.F) {
	f.Add("a", "b", "c", "a", "b\x00c", "")
	f.Add("vault_keys", "private_key", "7", "vault_keys", "private_key", "70")
	f.Fuzz(func(t *testing.T, t1, c1, r1, t2, c2, r2 string) {
		a, b := AAD{t1, c1, r1}, AAD{t2, c2, r2}
		ea, erra := a.Bytes(SSHKey)
		eb, errb := b.Bytes(SSHKey)
		if erra != nil || errb != nil {
			return
		}
		if a != b && bytes.Equal(ea, eb) {
			t.Fatalf("%+v and %+v encode alike", a, b)
		}
	})
}
