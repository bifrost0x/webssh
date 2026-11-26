package ldap

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"unicode/utf8"
)

// Limits of the directory files (app/ldap_service.py).
const (
	maxSecretBytes = 16 * 1024
	maxCABytes     = 1024 * 1024
)

// openRegular reads path, refusing links and anything but a regular file.
// It compares Lstat with the opened file, so a file swapped for a link
// between the check and the open is refused as well.
func openRegular(path string, limit int64) ([]byte, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, errors.New("not a regular file")
	}
	f, err := os.Open(path) // #nosec G304 -- LDAP_BIND_PASSWORD_FILE or LDAP_CA_FILE of the operator
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, nil, errors.New("file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > limit {
		return nil, nil, errors.New("file exceeds the size limit")
	}
	return data, info, nil
}

// readSecret applies the rules of _read_secret: a regular file, no group
// or other permission bits on Unix, at most 16 KiB, trailing CR and LF
// removed, not empty, no NUL, UTF-8.
func readSecret(path string) (string, error) {
	data, info, err := openRegular(path, maxSecretBytes)
	if err != nil {
		return "", fmt.Errorf("%w: bind password file: %w", ErrUnavailable, err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%w: bind password file permissions are too broad", ErrUnavailable)
	}
	secret := strings.TrimRight(string(data), "\r\n")
	if secret == "" || strings.ContainsRune(secret, 0) || !utf8.ValidString(secret) {
		return "", fmt.Errorf("%w: bind password file is invalid", ErrUnavailable)
	}
	return secret, nil
}

// loadCA reads LDAP_CA_FILE as validate_runtime_files accepts it: a
// regular file of 1 byte to 1 MiB, ASCII PEM with at least one
// certificate, every certificate parsable. Only these certificates are
// trusted for the directory: the Python release set the CA with the
// certificate policy "demand", so neither the system store nor
// REQUESTS_CA_BUNDLE applied to LDAP.
func loadCA(path string) (*x509.CertPool, error) {
	data, _, err := openRegular(path, maxCABytes)
	if err != nil {
		return nil, fmt.Errorf("%w: CA bundle: %w", ErrUnavailable, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: CA bundle is empty", ErrUnavailable)
	}
	for _, c := range data {
		if c > 0x7f {
			return nil, fmt.Errorf("%w: CA bundle is not ASCII", ErrUnavailable)
		}
	}
	pool := x509.NewCertPool()
	found := false
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" && block.Type != "X509 CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: CA bundle: %w", ErrUnavailable, err)
		}
		pool.AddCert(cert)
		found = true
	}
	if !found {
		return nil, fmt.Errorf("%w: CA bundle has no certificate", ErrUnavailable)
	}
	return pool, nil
}
