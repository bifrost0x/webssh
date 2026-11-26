package config

import (
	"io/fs"
	"strings"
	"testing"
	"time"
)

// The fuzz targets check that the parsers of untrusted environment values
// never panic or loop and that their results are stable. Agreement with
// Python is checked by the differential tests.

func FuzzPyInt(f *testing.F) {
	for _, s := range []string{"0", " -1_000 ", "٣٤", "+", "1__0", "\x1c1", strings.Repeat("9", 4301)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, ok := pyInt(s)
		if !ok {
			return
		}
		again, ok := pyInt(v.String())
		if !ok || again.Cmp(v) != 0 {
			t.Fatalf("%q -> %s does not parse back", s, v)
		}
	})
}

func FuzzPyURLSplit(f *testing.F) {
	for _, s := range []string{"https://a@b:1/p?q#f", "https://[::1]:x", "https://[v1.x]", "\x00 ldap://h", "https://℀"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		u, err := pyURLSplit(s)
		if err != nil {
			return
		}
		_ = u.hostname()
		_, _ = u.port()
		_ = u.hasCredentials()
	})
}

func FuzzPyIPNetwork(f *testing.F) {
	for _, s := range []string{"10.0.0.0/8", "10.0.0.0/255.0.0.0", "fd00::1%a", "::ffff:1.2.3.4", "1::", "10.0.0.0/0.255.255.255"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, err := pyIPNetwork(s)
		if err != nil {
			return
		}
		again, err := pyIPNetwork(n.String())
		if err != nil || !again.equal(n) {
			t.Fatalf("%q -> %s does not parse back: %v", s, n, err)
		}
		_ = n.subnetOf(allowlistableNetworks[4])
	})
}

func FuzzTailscaleTarget(f *testing.F) {
	for _, s := range []string{"host:22", "[::1]:2222", "a..b", "Host.Example.", "1.2.3.4:0"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		host, port, err := tailscaleTarget(s)
		if err != nil {
			return
		}
		if port < 1 || port > 65535 || host == "" {
			t.Fatalf("%q -> %q %d", s, host, port)
		}
		_, _ = smbTarget(s)
	})
}

func FuzzProxyCIDRs(f *testing.F) {
	f.Add("10.0.0.0/8, 192.0.2.1")
	f.Add("fe80::1%eth0")
	f.Fuzz(func(t *testing.T, s string) {
		prefixes, err := parseProxyCIDRs(s)
		if err != nil {
			return
		}
		for _, p := range prefixes {
			if !p.IsValid() || p != p.Masked() || p.Addr().Zone() != "" {
				t.Fatalf("%q -> invalid prefix %v", s, p)
			}
		}
	})
}

// FuzzLoad reads an environment of "NAME=value" lines.
func FuzzLoad(f *testing.F) {
	f.Add("CORS_ORIGINS=*\nALLOW_CORS_WILDCARD=true")
	f.Add("WEBAUTHN_ENABLED=true\nWEBAUTHN_ORIGIN=https://[::1")
	f.Add("LDAP_ENABLED=true\nLDAP_URL=ldap://h:0")
	f.Add("SSH_ALLOWED_INTERNAL_NETWORKS=fd00::%a/8\nTRUSTED_PROXY_CIDRS=10.0.0.0/8")
	f.Fuzz(func(t *testing.T, s string) {
		env := baseEnv()
		for line := range strings.SplitSeq(s, "\n") {
			if k, v, ok := strings.Cut(line, "="); ok {
				env[k] = v
			}
		}
		_, w1, err1 := Load(lookupMap(env))
		_, w2, err2 := Load(lookupMap(env))
		if (err1 == nil) != (err2 == nil) || err1 != nil && err1.Error() != err2.Error() || len(w1) != len(w2) {
			t.Fatal("Load is not deterministic")
		}
	})
}

// fakeFS is a file system of directories and symbolic links for realpath.
type fakeFS map[string]string // path -> link target; "" for a directory

type fakeInfo struct{ link bool }

func (i fakeInfo) Name() string { return "" }
func (i fakeInfo) Size() int64  { return 0 }
func (i fakeInfo) Mode() fs.FileMode {
	if i.link {
		return fs.ModeSymlink
	}
	return fs.ModeDir
}
func (i fakeInfo) ModTime() time.Time { return time.Time{} }
func (i fakeInfo) IsDir() bool        { return !i.link }
func (i fakeInfo) Sys() any           { return nil }

func (f fakeFS) Lstat(name string) (fs.FileInfo, error) {
	target, ok := f[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return fakeInfo{link: target != ""}, nil
}
func (f fakeFS) Stat(name string) (fs.FileInfo, error) { return f.Lstat(name) }
func (f fakeFS) Readlink(name string) (string, error) {
	if t := f[name]; t != "" {
		return t, nil
	}
	return "", fs.ErrInvalid
}
func (f fakeFS) ReadFile(string) ([]byte, error) { return nil, fs.ErrNotExist }

func FuzzRealpath(f *testing.F) {
	f.Add("/a/b/../c", "/a", "/b", "b", "../a")
	f.Add("/x/y", "/x", "/x/y", "/x", "y")
	f.Fuzz(func(t *testing.T, path, link1, target1, link2, target2 string) {
		fsys := fakeFS{}
		for _, l := range [][2]string{{link1, target1}, {link2, target2}} {
			if strings.HasPrefix(l[0], "/") && l[1] != "" {
				fsys[pyPath(l[0])] = l[1]
			}
		}
		done := make(chan string, 1)
		go func() { done <- pyRealpath(fsys, "/"+path) }()
		select {
		case got := <-done:
			if !strings.HasPrefix(got, "/") {
				t.Fatalf("realpath(%q) = %q is not absolute", path, got)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("realpath(%q) does not finish", path)
		}
	})
}
