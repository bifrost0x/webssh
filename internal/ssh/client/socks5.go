package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/bifrost0x/webssh/internal/fault"
)

// SOCKSError is a SOCKS5 failure with the stable code of the Python release
// (app/socks5_client.py). Proxy-supplied text is never included.
type SOCKSError struct{ Code string }

func (e *SOCKSError) Error() string { return "socks5: " + e.Code }

// socksReplyCodes maps the reply field of RFC 1928 to the codes.
var socksReplyCodes = map[byte]string{
	1: "socks_proxy_failure",
	2: "socks_not_allowed",
	3: "socks_network_unreachable",
	4: "socks_host_unreachable",
	5: "socks_connection_refused",
	6: "socks_ttl_expired",
	7: "socks_unsupported",
	8: "socks_unsupported",
}

// fault returns the catalog code of the failure; the socks_* codes are
// in the catalog with the spelling of the Python release.
func (e *SOCKSError) fault() fault.Code {
	if c := fault.Code(e.Code); strings.HasPrefix(e.Code, "socks_") && c.Known() {
		return c
	}
	return fault.SOCKSProtocolError
}

func socksFail(code string) error { return &SOCKSError{Code: code} }

// socksConnect runs the CONNECT handshake (RFC 1928, no authentication) on
// conn. dest is an IP literal or a name, as the network policy decided.
func socksConnect(ctx context.Context, conn net.Conn, dest string, port int) error {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	err := socksHandshake(conn, dest, port)
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func socksHandshake(rw io.ReadWriter, dest string, port int) error {
	request, err := connectRequest(dest, port)
	if err != nil {
		return err
	}
	if _, err := rw.Write([]byte{5, 1, 0}); err != nil {
		return socksIO(err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(rw, reply[:]); err != nil {
		return socksIO(err)
	}
	switch {
	case reply[0] != 5:
		return socksFail("socks_protocol_error")
	case reply[1] == 0xff:
		return socksFail("socks_auth_required")
	case reply[1] != 0:
		return socksFail("socks_protocol_error")
	}
	if _, err := rw.Write(request); err != nil {
		return socksIO(err)
	}
	return readConnectReply(rw)
}

func connectRequest(host string, port int) ([]byte, error) {
	if port < 1 || port > 65535 {
		return nil, socksFail("socks_protocol_error")
	}
	req := []byte{5, 1, 0}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return nil, socksFail("socks_protocol_error")
		}
		if addr.Is4() {
			req = append(req, 1)
		} else {
			req = append(req, 4)
		}
		req = append(req, addr.AsSlice()...)
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, socksFail("socks_protocol_error")
		}
		req = append(req, 3, byte(len(host))) // #nosec G115 -- at most 255, checked above
		req = append(req, host...)
	}
	return binary.BigEndian.AppendUint16(req, uint16(port)), nil // #nosec G115 -- port range checked above
}

// readConnectReply reads the CONNECT reply including the bound address,
// so the SSH handshake starts at the first byte after it.
func readConnectReply(r io.Reader) error {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return socksIO(err)
	}
	if head[0] != 5 || head[2] != 0 {
		return socksFail("socks_protocol_error")
	}
	if head[1] != 0 {
		if code, ok := socksReplyCodes[head[1]]; ok {
			return socksFail(code)
		}
		return socksFail("socks_protocol_error")
	}
	var skip int
	switch head[3] {
	case 1:
		skip = 4
	case 4:
		skip = 16
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return socksIO(err)
		}
		skip = int(n[0])
	default:
		return socksFail("socks_protocol_error")
	}
	if _, err := io.ReadFull(r, make([]byte, skip+2)); err != nil {
		return socksIO(err)
	}
	return nil
}

func socksIO(err error) error {
	if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
		return fmt.Errorf("%w: %w", socksFail("socks_timeout"), err)
	}
	return fmt.Errorf("%w: %w", socksFail("socks_protocol_error"), err)
}

// joinHostPort joins host and port for net dialers.
func joinHostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}
