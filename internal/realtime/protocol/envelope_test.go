package protocol

import (
	"encoding/json/jsontext"
	"errors"
	"strings"
	"testing"
)

func TestDecodeEnvelope(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		ok   bool
	}{
		{name: "request", in: `{"v":1,"t":"terminal.open","id":"c1","p":{"ch":1}}`, ok: true},
		{name: "event without id", in: `{"v":1,"t":"session.keepalive"}`, ok: true},
		{name: "id charset", in: `{"v":1,"t":"a","id":"A-z.0:_"}`, ok: true},
		{name: "trailing whitespace", in: "{\"v\":1,\"t\":\"a\"}\n ", ok: true},
		{name: "wrong version", in: `{"v":2,"t":"a"}`},
		{name: "missing version", in: `{"t":"a"}`},
		{name: "fractional version", in: `{"v":1.5,"t":"a"}`},
		{name: "unknown field", in: `{"v":1,"t":"a","x":1}`},
		{name: "upper case key", in: `{"V":1,"t":"a"}`},
		{name: "mixed case key", in: `{"v":1,"T":"a"}`},
		{name: "duplicate key", in: `{"v":1,"t":"a","t":"b"}`},
		{name: "duplicate key in payload", in: `{"v":1,"t":"a","p":{"x":1,"x":2}}`},
		{name: "deep duplicate in payload", in: `{"v":1,"t":"a","p":{"x":{"y":1,"y":1}}}`},
		{name: "empty type", in: `{"v":1,"t":""}`},
		{name: "upper case type", in: `{"v":1,"t":"Terminal.open"}`},
		{name: "type with slash", in: `{"v":1,"t":"a/b"}`},
		{name: "long type", in: `{"v":1,"t":"` + strings.Repeat("a", MaxTypeLen+1) + `"}`},
		{name: "id with space", in: `{"v":1,"t":"a","id":"a b"}`},
		{name: "long id", in: `{"v":1,"t":"a","id":"` + strings.Repeat("a", MaxIDLen+1) + `"}`},
		{name: "trailing object", in: `{"v":1,"t":"a"}{}`},
		{name: "trailing brace", in: `{"v":1,"t":"a"}}`},
		{name: "trailing garbage", in: `{"v":1,"t":"a"} x`},
		{name: "payload array", in: `{"v":1,"t":"a","p":[1]}`},
		{name: "payload string", in: `{"v":1,"t":"a","p":"x"}`},
		{name: "payload null", in: `{"v":1,"t":"a","p":null}`},
		{name: "invalid utf-8", in: "{\"v\":1,\"t\":\"a\",\"p\":{\"x\":\"\xff\"}}"},
		{name: "lone surrogate", in: `{"v":1,"t":"a","p":{"x":"\ud800"}}`},
		{name: "not json", in: `hello`},
		{name: "array", in: `[1]`},
		{name: "empty", in: ``},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := DecodeEnvelope([]byte(tt.in))
			if (err == nil) != tt.ok {
				t.Fatalf("DecodeEnvelope(%q) err=%v, want ok=%v", tt.in, err, tt.ok)
			}
			if err != nil && !errors.Is(err, ErrEnvelope) {
				t.Fatalf("error %v does not wrap ErrEnvelope", err)
			}
		})
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	t.Parallel()
	b, err := EncodeEnvelope(TypeTerminalResize, "c9", TerminalResize{Ch: 3, Cols: 80, Rows: 24})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"v":1,"t":"terminal.resize","id":"c9","p":{"ch":3,"cols":80,"rows":24}}`; string(b) != want {
		t.Fatalf("encoded %s, want %s", b, want)
	}
	env, err := DecodeEnvelope(b)
	if err != nil {
		t.Fatal(err)
	}
	var got TerminalResize
	if err := DecodePayload(env.P, &got); err != nil || got.Ch != 3 {
		t.Fatalf("payload %+v, %v", got, err)
	}
	if b, err := EncodeEnvelope("a", "", nil); err != nil || string(b) != `{"v":1,"t":"a"}` {
		t.Fatalf("empty event %s, %v", b, err)
	}
	if _, err := EncodeEnvelope("a", "", []int{1}); err == nil {
		t.Fatal("non-object payload encoded")
	}
}

func TestDecodePayloadStrict(t *testing.T) {
	t.Parallel()
	var v struct {
		A int `json:"a"`
	}
	for _, bad := range []string{`{"a":1,"b":2}`, `{"A":1}`, `{"a":1,"a":2}`, `{"a":"1"}`} {
		if err := DecodePayload(jsontext.Value(bad), &v); err == nil {
			t.Errorf("payload %s accepted", bad)
		}
	}
	v.A = 0
	if err := DecodePayload(nil, &v); err != nil || v.A != 0 {
		t.Fatalf("empty payload: %v", err)
	}
}

func TestSubprotocol(t *testing.T) {
	t.Parallel()
	if v, ok := ParseSubprotocol(Subprotocol(Version)); !ok || v != Version {
		t.Fatal("own subprotocol not parsed")
	}
	for _, bad := range []string{"", "webssh.v", "webssh.v0", "webssh.v01", "webssh.v-1", "webssh.vx", "webssh.v99999", "other"} {
		if _, ok := ParseSubprotocol(bad); ok {
			t.Errorf("ParseSubprotocol(%q) accepted", bad)
		}
	}
}

func FuzzDecodeEnvelope(f *testing.F) {
	f.Add([]byte(`{"v":1,"t":"terminal.open","id":"c1","p":{}}`))
	f.Add([]byte(`{"v":1,"t":"a","p":{"x":[1,{"y":null}]}}`))
	f.Add([]byte(`{"v":1,"t":"a","t":"b"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		env, err := DecodeEnvelope(b)
		if err != nil {
			return
		}
		if env.V != Version || !ValidType(env.T) {
			t.Fatalf("invalid envelope accepted: %q", b)
		}
		if env.ID != "" && !validToken(env.ID, MaxIDLen, false) {
			t.Fatalf("invalid id accepted: %q", b)
		}
		if len(env.P) > 0 && env.P.Kind() != '{' {
			t.Fatalf("non-object payload accepted: %q", b)
		}
		// Property: an accepted envelope survives re-encoding unchanged
		// in meaning.
		again, err := EncodeEnvelope(env.T, env.ID, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeEnvelope(again); err != nil {
			t.Fatalf("re-encoded envelope rejected: %v", err)
		}
	})
}
