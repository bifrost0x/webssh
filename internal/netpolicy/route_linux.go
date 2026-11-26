//go:build linux

package netpolicy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"
)

// This is the only file of internal/netpolicy that imports syscall; the
// architecture test lists every allowed importer (ADR 0010).
// It opens no process and needs no capability: RTM_GETROUTE and
// SO_BINDTODEVICE (Linux 5.7 and later) are available to unprivileged
// sockets.

const (
	routeQueryTimeout = time.Second
	routeRecvBuffer   = 32 << 10
	routeMaxDatagrams = 16
)

var routeSeq atomic.Uint32

func lookupRoute(ctx context.Context, addr netip.Addr) (Route, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return Route{}, fmt.Errorf("netpolicy: open netlink socket: %w", err)
	}
	defer func() { _ = syscall.Close(fd) }()

	// The receive timeout bounds the only blocking call. A context deadline
	// closer than the default shortens it; cancellation without a deadline
	// is observed after at most routeQueryTimeout.
	timeout := routeQueryTimeout
	if deadline, ok := ctx.Deadline(); ok {
		timeout = min(timeout, time.Until(deadline))
	}
	if timeout <= 0 {
		return Route{}, context.DeadlineExceeded
	}
	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return Route{}, fmt.Errorf("netpolicy: set netlink timeout: %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return Route{}, fmt.Errorf("netpolicy: bind netlink socket: %w", err)
	}
	local, err := syscall.Getsockname(fd)
	if err != nil {
		return Route{}, fmt.Errorf("netpolicy: netlink port id: %w", err)
	}
	self, ok := local.(*syscall.SockaddrNetlink)
	if !ok {
		return Route{}, errors.New("netpolicy: unexpected netlink socket address")
	}

	seq := routeSeq.Add(1)
	request, err := encodeRouteRequest(seq, self.Pid, addr)
	if err != nil {
		return Route{}, err
	}
	if err := syscall.Sendto(fd, request, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return Route{}, fmt.Errorf("netpolicy: send route request: %w", err)
	}

	buf := make([]byte, routeRecvBuffer)
	for range routeMaxDatagrams {
		if err := ctx.Err(); err != nil {
			return Route{}, err
		}
		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if errors.Is(err, syscall.EAGAIN) {
			return Route{}, fmt.Errorf("netpolicy: route lookup timed out: %w", context.DeadlineExceeded)
		}
		if err != nil {
			return Route{}, fmt.Errorf("netpolicy: receive route reply: %w", err)
		}
		// Only the kernel (port id 0) may answer; anything else is ignored.
		if sender, ok := from.(*syscall.SockaddrNetlink); !ok || sender.Pid != 0 {
			continue
		}
		reply, found, err := parseRouteReply(buf[:n], seq)
		if !found && err == nil {
			continue
		}
		if err != nil {
			if nlErr, ok := errors.AsType[netlinkError](err); ok {
				return Route{}, fmt.Errorf("netpolicy: route lookup: %w", syscall.Errno(nlErr.errno)) // #nosec G115 -- parser guarantees errno > 0
			}
			return Route{}, err
		}
		return routeFromReply(reply)
	}
	return Route{}, errors.New("netpolicy: no route reply from the kernel")
}

func routeFromReply(reply routeReply) (Route, error) {
	iface, err := net.InterfaceByIndex(int(reply.oif))
	if err != nil {
		return Route{}, fmt.Errorf("netpolicy: route interface %d: %w", reply.oif, err)
	}
	return Route{Interface: iface.Name, Local: reply.kind == rtnLocal, Table: reply.table}, nil
}

// interfaceDialer returns a dialer whose sockets are bound to one interface
// with SO_BINDTODEVICE, so a route change cannot move an admitted
// connection to another interface.
//
// The Python release sets IP_UNICAST_IF, which the kernel honours only for
// UDP and raw sockets; for its TCP connections it has no effect (K8 report,
// TestLabInterfacePinning).
func interfaceDialer(name string, timeout time.Duration) (*net.Dialer, error) {
	if _, err := net.InterfaceByName(name); err != nil {
		return nil, fmt.Errorf("netpolicy: interface %q: %w", name, err)
	}
	control := func(network, _ string, raw syscall.RawConn) error {
		if network != "tcp4" && network != "tcp6" {
			return fmt.Errorf("netpolicy: interface pinning needs tcp4 or tcp6, got %q", network)
		}
		var sockErr error
		if err := raw.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, name)
		}); err != nil {
			return err
		}
		if sockErr != nil {
			return fmt.Errorf("netpolicy: pin socket to %q: %w", name, sockErr)
		}
		return nil
	}
	return &net.Dialer{Timeout: timeout, Control: control}, nil
}
