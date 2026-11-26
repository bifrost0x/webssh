package netpolicy

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

// reply builds one netlink message with the given type, sequence and payload.
func reply(kind uint16, seq uint32, payload []byte) []byte {
	total := nlmsgHeaderLen + len(payload)
	b := make([]byte, align4(total))
	ne := binary.NativeEndian
	ne.PutUint32(b[0:], uint32(total))
	ne.PutUint16(b[4:], kind)
	ne.PutUint32(b[8:], seq)
	copy(b[nlmsgHeaderLen:], payload)
	return b
}

func attr(kind uint16, value []byte) []byte {
	b := make([]byte, align4(rtattrHeader+len(value)))
	binary.NativeEndian.PutUint16(b[0:], uint16(rtattrHeader+len(value)))
	binary.NativeEndian.PutUint16(b[2:], kind)
	copy(b[rtattrHeader:], value)
	return b
}

func u32(v uint32) []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, v)
	return b
}

func routePayload(family, table, kind uint8, attrs ...[]byte) []byte {
	rt := make([]byte, rtmsgLen)
	rt[0], rt[4], rt[7] = family, table, kind
	for _, a := range attrs {
		rt = append(rt, a...)
	}
	return rt
}

func TestEncodeRouteRequest(t *testing.T) {
	b, err := encodeRouteRequest(7, 42, netip.MustParseAddr("::ffff:100.100.100.10"))
	if err != nil {
		t.Fatal(err)
	}
	ne := binary.NativeEndian
	if got := ne.Uint32(b); int(got) != len(b) || len(b) != nlmsgHeaderLen+rtmsgLen+8 {
		t.Fatalf("length %d, buffer %d", got, len(b))
	}
	if ne.Uint16(b[4:]) != rtmGetRoute || ne.Uint16(b[6:]) != nlmFRequest {
		t.Fatalf("type/flags %x %x", ne.Uint16(b[4:]), ne.Uint16(b[6:]))
	}
	if ne.Uint32(b[8:]) != 7 || ne.Uint32(b[12:]) != 42 {
		t.Fatal("sequence or port id not encoded")
	}
	rt := b[nlmsgHeaderLen:]
	if rt[0] != familyInet || rt[1] != 32 {
		t.Fatalf("mapped address must be looked up as IPv4/32, got family %d len %d", rt[0], rt[1])
	}
	if got := netip.AddrFrom4([4]byte(rt[rtmsgLen+4 : rtmsgLen+8])); got.String() != "100.100.100.10" {
		t.Fatalf("dst %s", got)
	}
	b6, _ := encodeRouteRequest(1, 0, netip.MustParseAddr("fd7a:115c:a1e0::1"))
	if b6[nlmsgHeaderLen] != familyInet6 || b6[nlmsgHeaderLen+1] != 128 {
		t.Fatal("IPv6 request must use AF_INET6/128")
	}
	for _, bad := range []netip.Addr{{}, netip.MustParseAddr("fe80::1%eth0")} {
		if _, err := encodeRouteRequest(1, 0, bad); err == nil {
			t.Fatalf("%v accepted", bad)
		}
	}
}

func TestParseRouteReply(t *testing.T) {
	good := routePayload(familyInet, 254, 1, attr(rtaDst, []byte{100, 100, 100, 10}), attr(rtaTable, u32(52)), attr(rtaOIF, u32(3)))
	tests := []struct {
		name    string
		data    []byte
		found   bool
		wantErr bool
		want    routeReply
	}{
		{"route", reply(rtmNewRoute, 9, good), true, false, routeReply{family: familyInet, kind: 1, table: 52, oif: 3}},
		{"other sequence first", append(reply(rtmNewRoute, 8, good), reply(rtmNewRoute, 9, good)...), true, false, routeReply{family: familyInet, kind: 1, table: 52, oif: 3}},
		{"only other sequence", reply(rtmNewRoute, 8, good), false, false, routeReply{}},
		{"errno", reply(nlmsgError, 9, u32(uint32(0xffffff9b))), true, true, routeReply{}}, // -101 ENETUNREACH
		{"ack", reply(nlmsgError, 9, u32(0)), true, true, routeReply{}},
		{"done", reply(nlmsgDone, 9, nil), true, true, routeReply{}},
		{"short rtmsg", reply(rtmNewRoute, 9, []byte{2, 32}), true, true, routeReply{}},
		{"no oif", reply(rtmNewRoute, 9, routePayload(familyInet, 254, 1, attr(rtaDst, []byte{1, 2, 3, 4}))), true, true, routeReply{}},
		{"short oif", reply(rtmNewRoute, 9, routePayload(familyInet, 254, 1, attr(rtaOIF, []byte{1, 0}))), true, true, routeReply{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, found, err := parseRouteReply(tt.data, 9)
			if found != tt.found || (err != nil) != tt.wantErr || got != tt.want {
				t.Fatalf("got %+v found=%v err=%v", got, found, err)
			}
		})
	}
	var nlErr netlinkError
	if _, _, err := parseRouteReply(reply(nlmsgError, 9, u32(uint32(0xffffff9b))), 9); !errors.As(err, &nlErr) || nlErr.errno != 101 {
		t.Fatalf("errno not decoded: %v", err)
	}
}

func TestParseRouteReplyRejectsBadLengths(t *testing.T) {
	b := reply(rtmNewRoute, 9, routePayload(familyInet, 254, 1, attr(rtaOIF, u32(3))))
	binary.NativeEndian.PutUint32(b, uint32(len(b)+4)) // claims more than the datagram
	if _, _, err := parseRouteReply(b, 9); !errors.Is(err, errMalformedReply) {
		t.Fatalf("oversized message: %v", err)
	}
	binary.NativeEndian.PutUint32(b, 3) // shorter than a header
	if _, _, err := parseRouteReply(b, 9); !errors.Is(err, errMalformedReply) {
		t.Fatalf("undersized message: %v", err)
	}
	b = reply(rtmNewRoute, 9, routePayload(familyInet, 254, 1, attr(rtaOIF, u32(3))))
	binary.NativeEndian.PutUint16(b[nlmsgHeaderLen+rtmsgLen:], 200) // attribute overruns
	if _, _, err := parseRouteReply(b, 9); !errors.Is(err, errMalformedReply) {
		t.Fatalf("oversized attribute: %v", err)
	}
}

func FuzzParseRouteReply(f *testing.F) {
	f.Add(reply(rtmNewRoute, 1, routePayload(familyInet, 52, 1, attr(rtaOIF, u32(2)))))
	f.Add(reply(nlmsgError, 1, u32(0xffffff9b)))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		r, found, err := parseRouteReply(data, 1)
		if err == nil && found && r.oif == 0 {
			t.Fatal("accepted a route without output interface")
		}
	})
}
