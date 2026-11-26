package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"math/big"
	"sync"
	"testing"
	"time"
)

// A software authenticator for tests: it builds registrations and
// assertions with any flags, counter, handle or attestation, signed with
// real ES256, EdDSA and RS256 keys.

// cborPair keeps map entries in the order given.
type cborPair struct{ k, v any }

func cborEncode(v any) []byte {
	var out []byte
	head := func(major byte, n uint64) {
		switch {
		case n < 24:
			out = append(out, major<<5|byte(n))
		case n <= 0xff:
			out = append(out, major<<5|24, byte(n))
		case n <= 0xffff:
			out = append(out, major<<5|25)
			out = binary.BigEndian.AppendUint16(out, uint16(n))
		case n <= 0xffffffff:
			out = append(out, major<<5|26)
			out = binary.BigEndian.AppendUint32(out, uint32(n))
		default:
			out = append(out, major<<5|27)
			out = binary.BigEndian.AppendUint64(out, n)
		}
	}
	var enc func(any)
	enc = func(v any) {
		switch x := v.(type) {
		case int:
			enc(int64(x))
		case int64:
			if x >= 0 {
				head(0, uint64(x))
			} else {
				head(1, uint64(-1-x))
			}
		case []byte:
			head(2, uint64(len(x)))
			out = append(out, x...)
		case string:
			head(3, uint64(len(x)))
			out = append(out, x...)
		case []any:
			head(4, uint64(len(x)))
			for _, e := range x {
				enc(e)
			}
		case []cborPair:
			head(5, uint64(len(x)))
			for _, p := range x {
				enc(p.k)
				enc(p.v)
			}
		case bool:
			if x {
				out = append(out, 0xf5)
			} else {
				out = append(out, 0xf4)
			}
		case nil:
			out = append(out, 0xf6)
		default:
			panic("cborEncode: unsupported type")
		}
	}
	enc(v)
	return out
}

type softKey struct {
	alg    int64
	signer crypto.Signer
}

var (
	keyCache   = map[int64]*softKey{}
	keyCacheMu sync.Mutex
)

// newSoftKey returns a fresh key; RSA keys are generated once per test
// binary because generation is slow.
func newSoftKey(t testing.TB, alg int64) *softKey {
	t.Helper()
	var s crypto.Signer
	var err error
	switch alg {
	case AlgES256:
		s, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case AlgEdDSA:
		_, s, err = ed25519.GenerateKey(rand.Reader)
	case AlgRS256:
		keyCacheMu.Lock()
		defer keyCacheMu.Unlock()
		if k := keyCache[alg]; k != nil {
			return k
		}
		s, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		t.Fatal(err)
	}
	k := &softKey{alg: alg, signer: s}
	if alg == AlgRS256 {
		keyCache[alg] = k
	}
	return k
}

func (k *softKey) cose() []byte {
	switch pub := k.signer.Public().(type) {
	case *ecdsa.PublicKey:
		b, _ := pub.Bytes()
		return cborEncode([]cborPair{{1, 2}, {3, AlgES256}, {-1, 1}, {-2, b[1:33]}, {-3, b[33:]}})
	case ed25519.PublicKey:
		return cborEncode([]cborPair{{1, 1}, {3, AlgEdDSA}, {-1, 6}, {-2, []byte(pub)}})
	case *rsa.PublicKey:
		return cborEncode([]cborPair{{1, 3}, {3, AlgRS256}, {-1, pub.N.Bytes()}, {-2, big.NewInt(int64(pub.E)).Bytes()}})
	}
	panic("cose: unsupported key")
}

func (k *softKey) sign(t testing.TB, msg []byte) []byte {
	t.Helper()
	var sig []byte
	var err error
	if k.alg == AlgEdDSA {
		sig, err = k.signer.Sign(rand.Reader, msg, crypto.Hash(0))
	} else {
		d := sha256.Sum256(msg)
		sig, err = k.signer.Sign(rand.Reader, d[:], crypto.SHA256)
	}
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// authenticator is one credential of the software authenticator.
type authenticator struct {
	rp      RelyingParty
	key     *softKey
	id      []byte
	handle  string
	aaguid  [16]byte
	flags   byte
	counter uint32
}

func newAuthenticator(t testing.TB, rp RelyingParty, alg int64, handle string) *authenticator {
	t.Helper()
	a := &authenticator{rp: rp, key: newSoftKey(t, alg), id: make([]byte, 32), handle: handle, flags: FlagUP | FlagUV}
	_, _ = rand.Read(a.id)
	_, _ = rand.Read(a.aaguid[:])
	return a
}

func (a *authenticator) authData(flags byte, counter uint32, attested bool) []byte {
	h := sha256.Sum256([]byte(a.rp.ID))
	out := append([]byte(nil), h[:]...)
	if attested {
		flags |= FlagAT
	}
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, counter)
	if attested {
		out = append(out, a.aaguid[:]...)
		out = binary.BigEndian.AppendUint16(out, uint16(len(a.id)))
		out = append(out, a.id...)
		out = append(out, a.key.cose()...)
	}
	return out
}

func clientDataJSON(t testing.TB, typ string, challenge []byte, origin string, extra map[string]any) []byte {
	t.Helper()
	m := map[string]any{"type": typ, "challenge": encodeB64URL(challenge), "origin": origin, "crossOrigin": false}
	for k, v := range extra {
		m[k] = v
	}
	b, err := json.Marshal(m, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// attestation kinds of register.
const (
	attNone = iota
	attSelf
	attX5C
)

// register returns the create() response JSON for challenge.
func (a *authenticator) register(t testing.TB, challenge []byte, kind int) jsontext.Value {
	t.Helper()
	cdj := clientDataJSON(t, typeCreate, challenge, a.rp.Origin, nil)
	ad := a.authData(a.flags, a.counter, true)
	return credential(t, a.id, map[string]any{
		"clientDataJSON": cdj, "attestationObject": a.attestationObject(t, ad, cdj, kind), "transports": []string{"internal", "hybrid"},
	})
}

func (a *authenticator) attestationObject(t testing.TB, ad, cdj []byte, kind int) []byte {
	t.Helper()
	h := sha256.Sum256(cdj)
	signed := append(append([]byte(nil), ad...), h[:]...)
	var stmt []cborPair
	format := FormatNone
	switch kind {
	case attSelf:
		format = FormatPacked
		stmt = []cborPair{{"alg", a.key.alg}, {"sig", a.key.sign(t, signed)}}
	case attX5C:
		format = FormatPacked
		ak := newSoftKey(t, AlgES256)
		stmt = []cborPair{{"alg", AlgES256}, {"sig", ak.sign(t, signed)}, {"x5c", []any{attestationCert(t, ak, a.aaguid, false)}}}
	}
	if stmt == nil {
		stmt = []cborPair{}
	}
	return cborEncode([]cborPair{{"fmt", format}, {"attStmt", stmt}, {"authData", ad}})
}

func attestationCert(t testing.TB, k *softKey, aaguid [16]byte, ca bool) []byte {
	t.Helper()
	ext, err := asn1.Marshal(aaguid[:])
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{Country: []string{"AA"}, Organization: []string{"WebSSH tests"},
			OrganizationalUnit: []string{"Authenticator Attestation"}, CommonName: "soft authenticator"},
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<33, 0),
		BasicConstraintsValid: true, IsCA: ca,
		ExtraExtensions: []pkix.Extension{{Id: oidAAGUID, Value: ext}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.signer.Public(), k.signer)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// assertion options of the software authenticator.
type assertOpts struct {
	flags      byte
	counter    uint32
	handle     *string
	origin     string
	typ        string
	extra      map[string]any
	authData   func([]byte) []byte
	clientData func([]byte) []byte
}

// assert returns the get() response JSON for challenge. The counter
// advances unless opts sets one.
func (a *authenticator) assert(t testing.TB, challenge []byte, o assertOpts) jsontext.Value {
	t.Helper()
	if o.flags == 0 {
		o.flags = a.flags
	}
	if o.counter == 0 && a.counter > 0 {
		a.counter++
		o.counter = a.counter
	}
	if o.origin == "" {
		o.origin = a.rp.Origin
	}
	if o.typ == "" {
		o.typ = typeGet
	}
	handle := &a.handle
	if o.handle != nil {
		handle = o.handle
	}
	cdj := clientDataJSON(t, o.typ, challenge, o.origin, o.extra)
	if o.clientData != nil {
		cdj = o.clientData(cdj)
	}
	ad := a.authData(o.flags, o.counter, false)
	if o.authData != nil {
		ad = o.authData(ad)
	}
	h := sha256.Sum256(cdj)
	sig := a.key.sign(t, append(append([]byte(nil), ad...), h[:]...))
	resp := map[string]any{"clientDataJSON": cdj, "authenticatorData": ad, "signature": sig, "userHandle": nil}
	if *handle != "" {
		resp["userHandle"] = []byte(*handle)
	}
	return credential(t, a.id, resp)
}
