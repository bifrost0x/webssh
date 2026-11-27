// Package platform holds the host-facing start-up checks of WebSSH on
// Linux, the only platform it is built for (Docker on linux/amd64 and
// linux/arm64, Unraid).
//
// It prepares the data directory with owner-only access and checks the TZ
// time zone. The data directory and its logs and keys subdirectories get
// mode 0700, as the Python entrypoint does today.
//
// It imports only the standard library.
package platform
