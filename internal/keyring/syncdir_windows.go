//go:build windows

package keyring

// syncDir is a no-op on Windows: directories cannot be opened for fsync
// there, and NTFS journals renames and deletions itself.
func syncDir(string) error { return nil }
