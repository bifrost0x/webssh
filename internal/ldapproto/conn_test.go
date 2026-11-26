package ldapproto

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// testPKI is a CA and a server certificate for ldap.example.test.
type testPKI struct {
	pool   *x509.CertPool
	server tls.Certificate
}

var pki = sync.OnceValue(func() testPKI {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "ldap"},
		DNSNames: []string{"ldap.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &leafKey.PublicKey, key)
	if err != nil {
		panic(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return testPKI{pool: pool, server: tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}
})

// fakeServer answers one connection: plain answers the plaintext phase
// (StartTLS), and after a successful StartTLS or for ldaps:// secure
// answers each message over TLS. A nil answer sends nothing.
type fakeServer struct {
	ldaps  bool
	plain  func(req []byte) []byte
	secure func(req message) [][]byte

	seenPlain  chan []byte
	seenSecure chan message
}

func (s *fakeServer) dial(t *testing.T) DialFunc {
	t.Helper()
	s.seenPlain = make(chan []byte, 8)
	s.seenSecure = make(chan message, 8)
	// A loopback socket, not net.Pipe: TLS alerts need the buffering of a
	// real connection, or both sides block in a failed handshake.
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		go func() {
			defer ln.Close()
			if server, err := ln.Accept(); err == nil {
				s.serve(server)
			}
		}()
		return (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	}
}

func (s *fakeServer) serve(conn net.Conn) {
	defer conn.Close()
	defer close(s.seenSecure)
	if !s.ldaps {
		r := bufio.NewReader(conn)
		req, err := readMessage(r, maxSearchSize)
		if err == nil {
			s.seenPlain <- req
		}
		close(s.seenPlain)
		if err != nil {
			return
		}
		out := s.plain(req)
		if out == nil {
			<-time.After(2 * time.Second)
			return
		}
		if _, err := conn.Write(out); err != nil {
			return
		}
		res, err := parseMessage(out)
		if err != nil || res.op.tag != opExtendedResponse {
			return
		}
		if r, _, err := parseResult(res.op); err != nil || r.Code != ResultSuccess {
			return
		}
	} else {
		close(s.seenPlain)
	}
	tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{pki().server}, MinVersion: tls.VersionTLS12})
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	r := bufio.NewReader(tlsConn)
	for {
		raw, err := readMessage(r, maxSearchSize)
		if err != nil {
			return
		}
		msg, err := parseMessage(raw)
		if err != nil {
			return
		}
		s.seenSecure <- msg
		if msg.op.tag == opUnbindRequest {
			return
		}
		for _, out := range s.secure(msg) {
			if _, err := tlsConn.Write(out); err != nil {
				return
			}
		}
	}
}

var startTLSOK = func([]byte) []byte { return extendedResponse(1, 0) }

func testURL(t *testing.T, raw string) ServerURL {
	t.Helper()
	u, err := ParseServerURL(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func result(code ResultCode) []byte {
	var body []byte
	body = appendInt(body, tagEnumerated, int64(code))
	body = appendOctetString(body, tagOctetString, "")
	return appendOctetString(body, tagOctetString, "")
}

func extendedResponse(id int64, code int64) []byte {
	return envelope(id, appendTLV(nil, opExtendedResponse, result(ResultCode(code))))
}

func response(id int64, tag byte, code ResultCode) []byte {
	return envelope(id, appendTLV(nil, tag, result(code)))
}

func referralResponse(id int64, tag byte, urls ...string) []byte {
	var refs []byte
	for _, u := range urls {
		refs = appendOctetString(refs, tagOctetString, u)
	}
	body := append(result(ResultReferral), appendTLV(nil, tagResultReferral, refs)...)
	return envelope(id, appendTLV(nil, tag, body))
}

func entryMessage(id int64, dn string, attrs map[string][]string) []byte {
	var list []byte
	for name, values := range attrs {
		var set []byte
		for _, v := range values {
			set = appendOctetString(set, tagOctetString, v)
		}
		var pair []byte
		pair = appendOctetString(pair, tagOctetString, name)
		pair = appendTLV(pair, tagSet, set)
		list = appendTLV(list, tagSequence, pair)
	}
	var body []byte
	body = appendOctetString(body, tagOctetString, dn)
	body = appendTLV(body, tagSequence, list)
	return envelope(id, appendTLV(nil, opSearchEntry, body))
}

func referenceMessage(id int64, urls ...string) []byte {
	var body []byte
	for _, u := range urls {
		body = appendOctetString(body, tagOctetString, u)
	}
	return envelope(id, appendTLV(nil, opSearchReference, body))
}

func dialFake(t *testing.T, s *fakeServer, raw string) (*Conn, error) {
	t.Helper()
	return Dial(t.Context(), Config{URL: testURL(t, raw), RootCAs: pki().pool, Dial: s.dial(t)})
}

func TestDialRefusedStartTLSSendsNoBind(t *testing.T) {
	t.Parallel()
	s := &fakeServer{plain: func([]byte) []byte { return extendedResponse(1, 2) }}
	if _, err := dialFake(t, s, "ldap://ldap.example.test"); !errors.Is(err, ErrStartTLS) {
		t.Fatalf("want ErrStartTLS, got %v", err)
	}
	req := <-s.seenPlain
	if !bytes.Contains(req, []byte(oidStartTLS)) {
		t.Fatalf("client sent something other than StartTLS: %x", req)
	}
	if _, more := <-s.seenSecure; more {
		t.Fatal("client went on after the refused StartTLS")
	}
}

// TestDialRefusesDataAfterStartTLS is condition K7: bytes the server
// (or an attacker on the path) sends after the StartTLS response and
// before the handshake must not reach the TLS layer as protected data.
func TestDialRefusesDataAfterStartTLS(t *testing.T) {
	t.Parallel()
	injected := append(extendedResponse(1, 0), response(2, opBindResponse, ResultSuccess)...)
	s := &fakeServer{plain: func([]byte) []byte { return injected }}
	_, err := dialFake(t, s, "ldap://ldap.example.test")
	if !errors.Is(err, ErrStartTLS) {
		t.Fatalf("want ErrStartTLS, got %v", err)
	}
	if _, more := <-s.seenSecure; more {
		t.Fatal("client sent a protected message")
	}
}

func TestDialRejectsUnsolicitedAndMalformedReplies(t *testing.T) {
	t.Parallel()
	for name, reply := range map[string][]byte{
		"notice of disconnection": extendedResponse(0, 52),
		"wrong message id":        extendedResponse(7, 0),
		"indefinite length":       {0x30, 0x80, 0x00, 0x00},
		"oversized message":       {0x30, 0x84, 0x7f, 0xff, 0xff, 0xff},
		"length wraps on 32 bit":  {0x30, 0x84, 0xff, 0xff, 0xff, 0xff},
		"not a sequence":          {0x04, 0x00},
		"bind response":           response(1, opBindResponse, ResultSuccess),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := &fakeServer{plain: func([]byte) []byte { return reply }}
			if _, err := dialFake(t, s, "ldap://ldap.example.test"); !errors.Is(err, ErrStartTLS) {
				t.Fatalf("want ErrStartTLS, got %v", err)
			}
		})
	}
}

func TestDialHonoursContextDeadline(t *testing.T) {
	t.Parallel()
	s := &fakeServer{plain: func([]byte) []byte { return nil }}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := Dial(ctx, Config{URL: testURL(t, "ldap://ldap.example.test"), RootCAs: pki().pool, Dial: s.dial(t)})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("want deadline error quickly, got %v after %v", err, time.Since(start))
	}
}

func TestDialRequiresCAPool(t *testing.T) {
	t.Parallel()
	if _, err := Dial(t.Context(), Config{URL: testURL(t, "ldap://ldap.example.test")}); err == nil {
		t.Fatal("dial without CA pool must fail")
	}
}

func TestDialVerifiesCertificate(t *testing.T) {
	t.Parallel()
	for name, cfg := range map[string]Config{
		"unknown authority": {URL: testURL(t, "ldaps://ldap.example.test"), RootCAs: x509.NewCertPool()},
		"other name":        {URL: testURL(t, "ldaps://other.example.test"), RootCAs: pki().pool},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := &fakeServer{ldaps: true}
			cfg.Dial = s.dial(t)
			if _, err := Dial(t.Context(), cfg); err == nil {
				t.Fatal("handshake must fail")
			}
		})
	}
}

func TestBindRefusesEmptyCredentials(t *testing.T) {
	t.Parallel()
	c := &Conn{}
	for _, pair := range [][2]string{{"", "x"}, {"cn=a", ""}, {"", ""}} {
		if err := c.Bind(t.Context(), pair[0], pair[1]); !errors.Is(err, ErrEmptyPassword) {
			t.Fatalf("%q: want ErrEmptyPassword, got %v", pair, err)
		}
	}
}

func searchServer(ldaps bool, search func(id int64) [][]byte) *fakeServer {
	return &fakeServer{ldaps: ldaps, plain: startTLSOK, secure: func(m message) [][]byte {
		switch m.op.tag {
		case opBindRequest:
			parts, _ := m.op.children()
			if len(parts) == 3 && string(parts[2].content) == "secret" {
				return [][]byte{response(m.id, opBindResponse, ResultSuccess)}
			}
			if len(parts) == 3 && string(parts[2].content) == "refer" {
				return [][]byte{referralResponse(m.id, opBindResponse, "ldap://elsewhere.example.test/")}
			}
			return [][]byte{response(m.id, opBindResponse, ResultInvalidCredentials)}
		case opSearchRequest:
			return search(m.id)
		}
		return nil
	}}
}

func TestBindAndSearch(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"ldap://ldap.example.test", "ldaps://ldap.example.test"} {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			s := searchServer(raw[:5] == "ldaps", func(id int64) [][]byte {
				return [][]byte{
					entryMessage(id, "uid=alice,dc=example", map[string][]string{"entryUUID": {"u-1"}}),
					referenceMessage(id, "ldap://other.example.test/ou=x,dc=example??sub"),
					response(id, opSearchDone, ResultSuccess),
				}
			})
			c, err := dialFake(t, s, raw)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if err := c.Bind(t.Context(), "cn=svc", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("wrong password: %v", err)
			}
			var ref *ReferralError
			if err := c.Bind(t.Context(), "cn=svc", "refer"); !errors.As(err, &ref) || len(ref.URLs) != 1 {
				t.Fatalf("referral: %v", err)
			}
			if err := c.Bind(t.Context(), "cn=svc", "secret"); err != nil {
				t.Fatalf("bind: %v", err)
			}
			filter, _ := CompileFilter("(uid=alice)")
			res, err := c.Search(t.Context(), SearchRequest{BaseDN: "dc=example", Scope: ScopeSubtree, SizeLimit: 2, Filter: filter, Attributes: []string{"entryUUID"}})
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Entries) != 1 || res.Entries[0].DN != "uid=alice,dc=example" || string(res.Entries[0].Values("ENTRYUUID")[0]) != "u-1" || len(res.References) != 1 {
				t.Fatalf("result %+v", res)
			}
		})
	}
}

func TestSearchFailures(t *testing.T) {
	t.Parallel()
	entry := func(id int64) []byte { return entryMessage(id, "cn=x", map[string][]string{"a": {"1"}}) }
	cases := map[string]struct {
		answer func(id int64) [][]byte
		check  func(error) bool
	}{
		"server ignores the size limit": {func(id int64) [][]byte {
			return [][]byte{entry(id), entry(id), entry(id), response(id, opSearchDone, ResultSuccess)}
		}, func(err error) bool { return errors.Is(err, ErrSizeLimit) }},
		"size limit exceeded": {func(id int64) [][]byte {
			return [][]byte{entry(id), entry(id), response(id, opSearchDone, ResultSizeLimitExceeded)}
		}, func(err error) bool { return errors.Is(err, ErrSizeLimit) }},
		"base below a referral": {func(id int64) [][]byte {
			return [][]byte{referralResponse(id, opSearchDone, "ldap://elsewhere.example.test/dc=x")}
		}, func(err error) bool { var r *ReferralError; return errors.As(err, &r) }},
		"no such object": {func(id int64) [][]byte {
			return [][]byte{response(id, opSearchDone, ResultNoSuchObject)}
		}, func(err error) bool {
			var r *ResultError
			return errors.As(err, &r) && r.Result.Code == ResultNoSuchObject
		}},
		"notice of disconnection": {func(int64) [][]byte {
			return [][]byte{extendedResponse(0, 52)}
		}, func(err error) bool { return errors.Is(err, ErrConnClosed) }},
		"response for another message": {func(id int64) [][]byte {
			return [][]byte{response(id+5, opSearchDone, ResultSuccess)}
		}, func(err error) bool { return errors.Is(err, ErrMalformed) }},
		"unexpected operation": {func(id int64) [][]byte {
			return [][]byte{response(id, opBindResponse, ResultSuccess)}
		}, func(err error) bool { return errors.Is(err, ErrMalformed) }},
		"entry DN not UTF-8": {func(id int64) [][]byte {
			return [][]byte{entryMessage(id, "cn=\xff", nil)}
		}, func(err error) bool { return errors.Is(err, ErrMalformed) }},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c, err := dialFake(t, searchServer(false, tc.answer), "ldap://ldap.example.test")
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			filter, _ := CompileFilter("(a=1)")
			_, err = c.Search(t.Context(), SearchRequest{BaseDN: "dc=x", Scope: ScopeSubtree, SizeLimit: 2, Filter: filter})
			if !tc.check(err) {
				t.Fatalf("unexpected error %v", err)
			}
		})
	}
}

func TestSearchHonoursContext(t *testing.T) {
	t.Parallel()
	c, err := dialFake(t, searchServer(false, func(int64) [][]byte { return nil }), "ldap://ldap.example.test")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	filter, _ := CompileFilter("(a=1)")
	if _, err := c.Search(ctx, SearchRequest{BaseDN: "dc=x", SizeLimit: 2, Filter: filter}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline, got %v", err)
	}
	if err := c.Bind(t.Context(), "cn=a", "b"); !errors.Is(err, ErrConnClosed) {
		t.Fatalf("a timed-out connection must not be reused: %v", err)
	}
}

func FuzzParseMessage(f *testing.F) {
	f.Add(extendedResponse(1, 0))
	f.Add(entryMessage(2, "cn=a", map[string][]string{"a": {"1", "2"}}))
	f.Add(referralResponse(3, opSearchDone, "ldap://x/"))
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := parseMessage(data)
		if err != nil {
			return
		}
		// None of the response decoders may panic on any accepted envelope.
		_, _, _ = parseResult(msg.op)
		_, _ = parseEntry(msg.op)
		_, _ = parseURIs(msg.op)
	})
}

func FuzzReadMessage(f *testing.F) {
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01})
	f.Add([]byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := readMessage(bufio.NewReader(bytes.NewReader(data)), maxSearchSize)
		if err == nil && len(msg) > len(data) {
			t.Fatalf("read %d bytes from %d", len(msg), len(data))
		}
	})
}

func TestParseServerURL(t *testing.T) {
	t.Parallel()
	good := map[string]string{
		"ldap://Dir.Example.test":      "ldap://dir.example.test:389",
		"ldaps://dir.example.test":     "ldaps://dir.example.test:636",
		"ldap://[2001:db8::1]:1389":    "ldap://[2001:db8::1]:1389",
		"LDAP://dir.example.test.:389": "ldap://dir.example.test:389",
	}
	for in, want := range good {
		u, err := ParseServerURL(in)
		if err != nil || u.String() != want {
			t.Errorf("%q: got %v %v want %s", in, u, err, want)
		}
	}
	for _, in := range []string{"http://x", "ldap://", "ldap://u:p@x", "ldap://x/dc=a", "ldap://x/", "ldap://x?q", "ldap://x?",
		"ldap://x#f", "ldap://x:0", "ldap://x:99999", "ldapi:///", "ldap://x\n"} {
		if _, err := ParseServerURL(in); !errors.Is(err, ErrURL) {
			t.Errorf("%q: want ErrURL, got %v", in, err)
		}
	}
}
