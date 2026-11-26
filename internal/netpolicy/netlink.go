package netpolicy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// Netlink route message layout from linux/netlink.h and linux/rtnetlink.h.
// The encoder and parser have no syscall dependency, so they are tested and
// fuzzed on every platform; only route_linux.go talks to the kernel.
const (
	nlmsgHeaderLen = 16
	rtmsgLen       = 12
	rtattrHeader   = 4

	nlmsgError  = 2
	nlmsgDone   = 3
	rtmNewRoute = 24
	rtmGetRoute = 26
	nlmFRequest = 1

	rtaDst   = 1
	rtaOIF   = 4
	rtaTable = 15

	rtnLocal = 2

	// rtmFLookupTable asks the kernel to report the table that matched
	// (Linux 4.4+); without it the reply always names the main table.
	rtmFLookupTable = 0x1000

	familyInet  = 2
	familyInet6 = 10
)

// errMalformedReply reports a kernel reply that does not parse. The caller
// treats it like any other failed lookup: the route is unknown.
var errMalformedReply = errors.New("netpolicy: malformed netlink route reply")

// netlinkError carries the errno of an NLMSG_ERROR reply without importing
// syscall here; route_linux.go converts it for messages.
type netlinkError struct{ errno int32 }

func (e netlinkError) Error() string {
	return fmt.Sprintf("netpolicy: route lookup failed with errno %d", e.errno)
}

// routeReply is the part of an RTM_NEWROUTE answer the policy needs.
type routeReply struct {
	family uint8
	kind   uint8 // rtm_type, RTN_LOCAL for this host's own addresses
	table  uint32
	oif    uint32
}

func align4(n int) int { return (n + 3) &^ 3 }

// encodeRouteRequest builds one RTM_GETROUTE request for an exact address.
// Without NLM_F_DUMP the kernel runs a FIB lookup that follows the policy
// rules, so tailscaled's table 52 is honoured.
func encodeRouteRequest(seq, portID uint32, addr netip.Addr) ([]byte, error) {
	if !addr.IsValid() || addr.Zone() != "" {
		return nil, errors.New("netpolicy: route lookup needs a plain IP address")
	}
	addr = addr.Unmap()
	family := uint8(familyInet)
	if addr.Is6() {
		family = familyInet6
	}
	dst := addr.AsSlice()
	attrLen := rtattrHeader + len(dst)
	total := nlmsgHeaderLen + rtmsgLen + align4(attrLen)
	b := make([]byte, total)
	ne := binary.NativeEndian
	ne.PutUint32(b[0:], uint32(total)) // #nosec G115 -- at most 48 bytes
	ne.PutUint16(b[4:], rtmGetRoute)
	ne.PutUint16(b[6:], nlmFRequest)
	ne.PutUint32(b[8:], seq)
	ne.PutUint32(b[12:], portID)
	rt := b[nlmsgHeaderLen:]
	rt[0] = family
	rt[1] = uint8(addr.BitLen()) // #nosec G115 -- 32 or 128; rtm_dst_len: exact host route
	ne.PutUint32(rt[8:], rtmFLookupTable)
	attr := rt[rtmsgLen:]
	ne.PutUint16(attr[0:], uint16(attrLen)) // #nosec G115 -- at most 20 bytes
	ne.PutUint16(attr[2:], rtaDst)
	copy(attr[rtattrHeader:], dst)
	return b, nil
}

// parseRouteReply scans one datagram for the answer to seq. It returns
// found=false when the datagram holds only unrelated messages. Lengths are
// checked before every slice operation; a malformed datagram is an error.
func parseRouteReply(b []byte, seq uint32) (reply routeReply, found bool, err error) {
	ne := binary.NativeEndian
	for off := 0; off+nlmsgHeaderLen <= len(b); {
		length := int(ne.Uint32(b[off:]))
		kind := ne.Uint16(b[off+4:])
		msgSeq := ne.Uint32(b[off+8:])
		if length < nlmsgHeaderLen || length > len(b)-off {
			return routeReply{}, false, errMalformedReply
		}
		payload := b[off+nlmsgHeaderLen : off+length]
		next := off + align4(length)
		if msgSeq != seq {
			off = next
			continue
		}
		switch kind {
		case nlmsgError:
			if len(payload) < 4 {
				return routeReply{}, false, errMalformedReply
			}
			errno := -int32(ne.Uint32(payload)) // #nosec G115 -- the kernel sends a negative errno as two's complement
			if errno <= 0 {
				// An acknowledgement carries no route; still a failed lookup.
				return routeReply{}, true, errMalformedReply
			}
			return routeReply{}, true, netlinkError{errno: errno}
		case nlmsgDone:
			return routeReply{}, true, errMalformedReply
		case rtmNewRoute:
			r, err := parseRoute(payload)
			return r, true, err
		}
		off = next
	}
	return routeReply{}, false, nil
}

func parseRoute(payload []byte) (routeReply, error) {
	if len(payload) < rtmsgLen {
		return routeReply{}, errMalformedReply
	}
	ne := binary.NativeEndian
	r := routeReply{family: payload[0], table: uint32(payload[4]), kind: payload[7]}
	attrs := payload[rtmsgLen:]
	for off := 0; off+rtattrHeader <= len(attrs); {
		length := int(ne.Uint16(attrs[off:]))
		kind := ne.Uint16(attrs[off+2:])
		if length < rtattrHeader || length > len(attrs)-off {
			return routeReply{}, errMalformedReply
		}
		value := attrs[off+rtattrHeader : off+length]
		switch kind {
		case rtaOIF:
			if len(value) < 4 {
				return routeReply{}, errMalformedReply
			}
			r.oif = ne.Uint32(value)
		case rtaTable:
			if len(value) < 4 {
				return routeReply{}, errMalformedReply
			}
			r.table = ne.Uint32(value)
		}
		off += align4(length)
	}
	if r.oif == 0 {
		return routeReply{}, errMalformedReply
	}
	return r, nil
}
