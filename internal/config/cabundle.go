package config

import (
	"crypto/x509"
	"errors"
	"fmt"
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
		for _, e := range entries {
			if e.Type().IsRegular() {
				files = append(files, filepath.Join(b.Path, e.Name()))
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

var errTooLarge = errors.New("file too large")

func readBounded(name string, limit int64) ([]byte, error) {
	info, err := os.Stat(name)
	if err != nil {
		return nil, err
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s: %w", name, errTooLarge)
	}
	return os.ReadFile(name) // #nosec G304 -- the trust anchors the operator names in REQUESTS_CA_BUNDLE or CURL_CA_BUNDLE
}
