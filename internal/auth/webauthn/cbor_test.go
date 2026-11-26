package webauthn

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestCBORAccepts(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		in   string
		want any
	}{
		"small int":         {"17", int64(23)},
		"one byte int":      {"1818", int64(24)},
		"negative":          {"26", int64(-7)},
		"two byte negative": {"390100", int64(-257)},
		"non-minimal head":  {"1900 05", int64(5)},
		"min int64":         {"3b7fffffffffffffff", int64(-1 << 63)},
		"byte string":       {"43010203", []byte{1, 2, 3}},
		"text":              {"63616c67", "alg"},
		"empty map":         {"a0", cborMap{}},
		"array":             {"820102", []any{int64(1), int64(2)}},
		"simple values":     {"83f4f5f6", []any{false, true, nil}},
		"text and int keys": {"a201020363616c67", cborMap{int64(1): int64(2), int64(3): "alg"}},
	} {
		t.Run(name, func(t *testing.T) {
			v, err := decodeCBOR(mustHex(t, c.in))
			if err != nil {
				t.Fatal(err)
			}
			if !cborEqual(v, c.want) {
				t.Fatalf("%#v, want %#v", v, c.want)
			}
		})
	}
}

func TestCBORRefuses(t *testing.T) {
	t.Parallel()
	deep := bytes.Repeat([]byte{0x81}, cborMaxDepth+1)
	deep = append(deep, 0)
	for name, in := range map[string][]byte{
		"empty":             {},
		"trailing":          mustHex(t, "0000"),
		"truncated head":    mustHex(t, "19 00"),
		"truncated string":  mustHex(t, "43 0102"),
		"indefinite bytes":  mustHex(t, "5f 41 00 ff"),
		"indefinite map":    mustHex(t, "bf ff"),
		"break":             mustHex(t, "ff"),
		"reserved info":     mustHex(t, "1c"),
		"tag":               mustHex(t, "c0 00"),
		"half float":        mustHex(t, "f9 3c00"),
		"double":            mustHex(t, "fb 3ff0000000000000"),
		"undefined":         mustHex(t, "f7"),
		"simple 16":         mustHex(t, "f0"),
		"two byte simple":   mustHex(t, "f8 20"),
		"uint beyond int64": mustHex(t, "1b 8000000000000000"),
		"nint beyond int64": mustHex(t, "3b 8000000000000000"),
		"invalid UTF-8":     mustHex(t, "61 ff"),
		"duplicate key":     mustHex(t, "a2 01 00 01 00"),
		"byte string key":   mustHex(t, "a1 41 00 00"),
		"array key":         mustHex(t, "a1 80 00"),
		"too deep":          deep,
		"array too long":    append(mustHex(t, "98 41"), make([]byte, 65)...),
		"map too long":      mustHex(t, "b8 41"),
		"string too long":   mustHex(t, "5a 00010001"),
		"huge length":       mustHex(t, "5b ffffffffffffffff"),
	} {
		if v, err := decodeCBOR(in); !errors.Is(err, errCBOR) {
			t.Errorf("%s: %#v, %v", name, v, err)
		}
	}
}

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(string(bytes.ReplaceAll([]byte(s), []byte(" "), nil)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func cborEqual(a, b any) bool {
	switch x := a.(type) {
	case []byte:
		y, ok := b.([]byte)
		return ok && bytes.Equal(x, y)
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !cborEqual(x[i], y[i]) {
				return false
			}
		}
		return true
	case cborMap:
		y, ok := b.(cborMap)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			if !cborEqual(v, y[k]) {
				return false
			}
		}
		return true
	}
	return a == b
}

func TestCOSERefuses(t *testing.T) {
	t.Parallel()
	ec := newSoftKey(t, AlgES256)
	pub, _ := ec.signer.Public().(interface{ Bytes() ([]byte, error) }).Bytes()
	x, y := pub[1:33], pub[33:]
	badY := bytes.Clone(y)
	badY[31] ^= 1
	ed := newSoftKey(t, AlgEdDSA).cose()
	if _, err := ParseCOSEKey(ed); err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string][]byte{
		"not a map":           cborEncode([]any{int64(1)}),
		"missing alg":         cborEncode([]cborPair{{1, 2}, {-1, 1}, {-2, x}, {-3, y}}),
		"ES384 alg":           cborEncode([]cborPair{{1, 2}, {3, -35}, {-1, 2}, {-2, x}, {-3, y}}),
		"wrong curve":         cborEncode([]cborPair{{1, 2}, {3, -7}, {-1, 2}, {-2, x}, {-3, y}}),
		"point off the curve": cborEncode([]cborPair{{1, 2}, {3, -7}, {-1, 1}, {-2, x}, {-3, badY}}),
		"short x":             cborEncode([]cborPair{{1, 2}, {3, -7}, {-1, 1}, {-2, x[1:]}, {-3, y}}),
		"kty/alg mismatch":    cborEncode([]cborPair{{1, 1}, {3, -7}, {-1, 1}, {-2, x}, {-3, y}}),
		"Ed448":               cborEncode([]cborPair{{1, 1}, {3, -8}, {-1, 7}, {-2, make([]byte, 57)}}),
		"RSA 512 bits":        cborEncode([]cborPair{{1, 3}, {3, -257}, {-1, append([]byte{0x80}, make([]byte, 62)...)}, {-2, []byte{1, 0, 1}}}),
		"RSA even exponent":   cborEncode([]cborPair{{1, 3}, {3, -257}, {-1, append(append([]byte{0x80}, make([]byte, 254)...), 1)}, {-2, []byte{1, 0, 0}}}),
		"RSA exponent 1":      cborEncode([]cborPair{{1, 3}, {3, -257}, {-1, append(append([]byte{0x80}, make([]byte, 254)...), 1)}, {-2, []byte{1}}}),
		"RSA even modulus":    cborEncode([]cborPair{{1, 3}, {3, -257}, {-1, append([]byte{0x80}, make([]byte, 255)...)}, {-2, []byte{1, 0, 1}}}),
		"trailing":            append(bytes.Clone(ed), 0),
	} {
		if _, err := ParseCOSEKey(key); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// FuzzCBOR checks that the decoder never panics, never reads past its
// input and that what it accepts re-encodes to an equal value.
func FuzzCBOR(f *testing.F) {
	for _, s := range []string{"a0", "a201020363616c6726", "83f4f5f6", "5f4100ff", "c000", "a2010001 00", "3b7fffffffffffffff"} {
		f.Add(mustHex(f, s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, n, err := decodeCBORPrefix(data)
		if err != nil {
			return
		}
		if n <= 0 || n > len(data) {
			t.Fatalf("consumed %d of %d", n, len(data))
		}
		again, err := decodeCBOR(cborEncode(toEncodable(v)))
		if err != nil || !cborEqual(v, again) {
			t.Fatalf("round trip: %#v -> %#v, %v", v, again, err)
		}
	})
}

func toEncodable(v any) any {
	switch x := v.(type) {
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = toEncodable(x[i])
		}
		return out
	case cborMap:
		out := make([]cborPair, 0, len(x))
		for k, val := range x {
			out = append(out, cborPair{k, toEncodable(val)})
		}
		return out
	}
	return v
}

// FuzzCOSEKey checks that key parsing never panics and that every accepted
// key is one of the three algorithms.
func FuzzCOSEKey(f *testing.F) {
	f.Add(newSoftKey(f, AlgES256).cose())
	f.Add(newSoftKey(f, AlgEdDSA).cose())
	f.Add(newSoftKey(f, AlgRS256).cose())
	f.Fuzz(func(t *testing.T, data []byte) {
		k, err := ParseCOSEKey(data)
		if err != nil {
			return
		}
		if k.Alg != AlgES256 && k.Alg != AlgEdDSA && k.Alg != AlgRS256 {
			t.Fatalf("alg %d", k.Alg)
		}
		if k.Verify([]byte("m"), []byte("not a signature")) == nil {
			t.Fatal("garbage signature verified")
		}
	})
}

// FuzzAssertion feeds arbitrary authenticator data, client data and
// signatures through the assertion check; nothing may verify without a
// valid signature of the test key.
func FuzzAssertion(f *testing.F) {
	a := newAuthenticator(f, testRP, AlgES256, "7")
	key, err := ParseCOSEKey(a.key.cose())
	if err != nil {
		f.Fatal(err)
	}
	ch := challenge32()
	valid, err := ParseAssertion(a.assert(f, ch, assertOpts{counter: 1}))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid.authData, valid.clientData, valid.signature)
	f.Fuzz(func(t *testing.T, authData, clientData, sig []byte) {
		asn := Assertion{CredentialID: a.id, UserHandle: []byte("7"), authData: authData, clientData: clientData, signature: sig}
		_, err := testRP.Verify(asn, Stored{Key: key, UserHandle: "7"}, Expect{Challenge: ch})
		if err == nil && !(bytes.Equal(authData, valid.authData) && bytes.Equal(clientData, valid.clientData)) {
			// ECDSA signatures are malleable only through the encoding;
			// any accepted input must carry the signed bytes.
			t.Fatalf("verified other data: %x %q", authData, clientData)
		}
	})
}
