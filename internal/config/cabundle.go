package config

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// maxCABundleFile bounds one certificate file read from the bundle.
const maxCABundleFile = 16 << 20

// CertPool returns the system trust store with the certificates of the
// bundle added. The bundle is a PEM file or, as requests accepts, a
// directory whose regular files hold PEM certificates. Without a bundle it
// returns the system trust store.
func (b CABundle) CertPool() (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if b.Path == "" {
		return pool, nil
	}
	files := []string{b.Path}
	info, err := os.Stat(b.Path)
	if err != nil {
		return nil, fmt.Errorf("config: %s: %w", b.Variable, err)
	}
	if info.IsDir() {
		entries, err := os.ReadDir(b.Path)
		if err != nil {
			return nil, fmt.Errorf("config: %s: %w", b.Variable, err)
		}
		files = files[:0]
		// Hashed CApath directories (c_rehash) hold links, so links are
		// followed. Unlike OpenSSL, every regular file counts, not only
		// the hashed names.
		for _, e := range entries {
			p := filepath.Join(b.Path, e.Name())
			if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
				files = append(files, p)
			}
		}
	}
	added := false
	for _, name := range files {
		data, err := readBounded(name, maxCABundleFile)
		if err != nil {
			return nil, fmt.Errorf("config: %s: %w", b.Variable, err)
		}
		if pool.AppendCertsFromPEM(data) {
			added = true
		}
	}
	if !added {
		return nil, fmt.Errorf("config: %s: %s holds no PEM certificate", b.Variable, b.Path)
	}
	return pool, nil
}

var (
	errTooLarge   = errors.New("file too large")
	errNotRegular = errors.New("not a regular file")
)

// readBounded reads a regular file of at most limit bytes. The checks run
// on the open descriptor, so a device, a FIFO or a file swapped in after
// the check is never read without bound.
func readBounded(name string, limit int64) (data []byte, err error) {
	f, err := os.Open(name) // #nosec G304 -- paths the operator names: trust anchors, the TZ zone file, DATA_DIR/secret_key
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w", name, errNotRegular)
	}
	data, err = io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: %w", name, errTooLarge)
	}
	return data, nil
}
