// Package platform holds what differs between the operating systems WebSSH
// runs on.
//
// It prepares the data directory with owner-only access, sends readiness
// and stop notifications to systemd and checks the TZ time zone. On Unix the
// data directory and its logs and keys subdirectories get mode 0700, as the
// Python entrypoint does today. Owner-only access on Windows (a protected
// ACL) and running as a Windows service follow with the Windows release;
// until then preparing a data directory fails there instead of leaving it
// open.
//
// It imports only the standard library.
package platform
