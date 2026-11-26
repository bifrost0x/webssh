//go:build !linux

package platform

// Notify does nothing outside Linux; only systemd uses the protocol.
func Notify(string) (bool, error) { return false, nil }
