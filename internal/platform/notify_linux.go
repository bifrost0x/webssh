//go:build linux

package platform

import (
	"errors"
	"fmt"
	"net"
	"os"
)

// Notify sends one sd_notify(3) message, such as NotifyReady, to the socket
// in NOTIFY_SOCKET. It reports false without error when the process does not
// run under a service manager that asked for notifications. The protocol is
// a single datagram on a Unix socket, so no library is needed.
func Notify(state string) (bool, error) {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return false, nil
	}
	if socket[0] != '/' && socket[0] != '@' {
		// vsock and other transports are for virtual machines.
		return false, fmt.Errorf("notify: unsupported NOTIFY_SOCKET %q", socket)
	}
	// A leading '@' selects the abstract namespace; package net handles it.
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return false, fmt.Errorf("notify: %w", err)
	}
	if _, err := conn.Write([]byte(state)); err != nil {
		return false, fmt.Errorf("notify: %w", errors.Join(err, conn.Close()))
	}
	if err := conn.Close(); err != nil {
		return false, fmt.Errorf("notify: %w", err)
	}
	return true, nil
}
