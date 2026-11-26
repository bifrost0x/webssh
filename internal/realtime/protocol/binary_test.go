package protocol

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	t.Parallel()
	for _, f := range []Frame{
		{Kind: KindInput, Channel: 7, Seq: 1, Data: []byte("ls\r")},
		{Kind: KindInput, Flags: FlagWantAck, Channel: 1<<32 - 1, Seq: 1<<64 - 1, Data: []byte{0, 0xff}},
		{Kind: KindAck, Channel: 2, Seq: 99},
		{Kind: KindOutput, Flags: FlagReset | FlagReplay, Channel: 1, Seq: 5, Data: []byte("\x1b[2J")},
	} {
		got, err := DecodeFrame(AppendFrame(nil, f), 1024)
		if err != nil {
			t.Fatalf("%+v: %v", f, err)
		}
		if got.Kind != f.Kind || got.Flags != f.Flags || got.Channel != f.Channel || got.Seq != f.Seq || !bytes.Equal(got.Data, f.Data) {
			t.Fatalf("round trip %+v -> %+v", f, got)
		}
	}
}

func TestDecodeFrameRejects(t *testing.T) {
	t.Parallel()
	cases := map[string][]byte{
		"short":          make([]byte, HeaderLen-1),
		"unknown kind":   AppendFrame(nil, Frame{Kind: 9}),
		"empty input":    AppendFrame(nil, Frame{Kind: KindInput}),
		"oversize input": AppendFrame(nil, Frame{Kind: KindInput, Data: make([]byte, 17)}),
		"input flags":    AppendFrame(nil, Frame{Kind: KindInput, Flags: 0x80, Data: []byte("x")}),
		"ack with data":  AppendFrame(nil, Frame{Kind: KindAck, Data: []byte("x")}),
		"ack with flags": AppendFrame(nil, Frame{Kind: KindAck, Flags: 1}),
	}
	for name, b := range cases {
		if _, err := DecodeFrame(b, 16); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func FuzzDecodeFrame(f *testing.F) {
	f.Add(AppendFrame(nil, Frame{Kind: KindInput, Channel: 1, Seq: 1, Data: []byte("a")}))
	f.Add(AppendFrame(nil, Frame{Kind: KindAck, Channel: 1, Seq: 1}))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		fr, err := DecodeFrame(b, 4096)
		if err != nil {
			return
		}
		// Property: whatever decodes, re-encodes to the same bytes.
		if !bytes.Equal(AppendFrame(nil, fr), b) {
			t.Fatalf("re-encode differs for %x", b)
		}
	})
}
