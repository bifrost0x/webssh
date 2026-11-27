package smb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

func TestLabConnect(t *testing.T) {
	for _, tg := range labTargets(t) {
		t.Run(tg.name, func(t *testing.T) {
			b := connectLab(t, tg, nil)
			if got := uint16(b.Cipher()); got != tg.cipher {
				t.Errorf("cipher %#x, want %#x", got, tg.cipher)
			}
			if b.security.Dialect != 0x311 || !b.security.EncryptData || !b.security.SigningRequired {
				t.Errorf("security %+v", b.security)
			}
			a := b.RootAccess()
			if a.List != files.AccessGranted || a.CreateFile != files.AccessGranted {
				t.Errorf("root access %+v", a)
			}
			d := b.Descriptor()
			if d.Label != tg.share+" on 127.0.0.1" || d.Endpoint != "127.0.0.1/"+tg.share || d.Protocol != "SMB 3.1.1" {
				t.Errorf("descriptor %+v", d)
			}
			if h, err := b.Home(t.Context()); err != nil || h != "/" {
				t.Errorf("home %q %v", h, err)
			}
		})
	}
}

func TestLabConnectRefusals(t *testing.T) {
	for _, tg := range labTargets(t) {
		t.Run(tg.name, func(t *testing.T) {
			p := newProxy(t, tg.port)
			cfg := labConfig(t, p.port(), p.dial)
			bad := tg.target()
			bad.Password = []byte("wrong-" + tg.password)
			_, err := Connect(t.Context(), cfg, bad)
			wantCode(t, err, fault.SMBAuthenticationRequired)
			if d := DiagnosticOf(err); d.NtStatus != "0xC000006D" || d.Phase != PhaseSessionAuthentication {
				t.Errorf("diagnostic %+v", d)
			}
			dials := p.dials.Load()
			for _, c := range []struct {
				name string
				edit func(*Target)
				code fault.Code
			}{
				{"empty user", func(t *Target) { t.Username = "" }, fault.InvalidRequest},
				{"empty password", func(t *Target) { t.Password = nil }, fault.InvalidRequest},
				{"admin share", func(t *Target) { t.Share = "C$" }, fault.InvalidRequest},
				{"host not allowed", func(t *Target) { t.Host = "127.0.0.2" }, fault.SMBTargetNotAllowed},
			} {
				tt := tg.target()
				c.edit(&tt)
				_, err := Connect(t.Context(), cfg, tt)
				if fault.CodeOf(err) != c.code {
					t.Errorf("%s: code %q, want %q", c.name, fault.CodeOf(err), c.code)
				}
			}
			if p.dials.Load() != dials {
				t.Errorf("refused input was dialled")
			}
			missing := tg.target()
			missing.Share = "NoSuchShare"
			_, err = Connect(t.Context(), cfg, missing)
			wantCode(t, err, fault.ShareUnavailable)
		})
	}
}

func TestLabFileOperations(t *testing.T) {
	for _, tg := range labTargets(t) {
		t.Run(tg.name, func(t *testing.T) {
			ctx := t.Context()
			b := connectLab(t, tg, nil)
			dir := labDir(t, b)
			wantCode(t, b.Mkdir(ctx, dir), fault.FileConflict)
			wantCode(t, b.Mkdir(ctx, dir+"/missing/sub"), fault.FileNotFound)
			if err := b.Mkdir(ctx, dir+"/sub"); err != nil {
				t.Fatal(err)
			}
			res := writeFile(t, b, dir+"/sub/a.txt", "hello world", files.WriteOptions{Exclusive: true})
			sum := sha256.Sum256([]byte("hello world"))
			if res.Revision != hex.EncodeToString(sum[:]) || res.Size != 11 {
				t.Errorf("result %+v", res)
			}
			_, err := b.Write(ctx, dir+"/sub/a.txt", strings.NewReader("x"), files.WriteOptions{Exclusive: true, Size: 1})
			wantCode(t, err, fault.FileConflict)
			e, err := b.Stat(ctx, dir+"/sub/a.txt", false)
			if err != nil || e.Size != 11 || e.IsDir || e.Mode != 0o100666 || e.Name != "a.txt" {
				t.Errorf("stat %+v %v", e, err)
			}
			d, err := b.Stat(ctx, dir+"/sub", false)
			if err != nil || !d.IsDir || d.Mode != 0o040111|0o666 {
				t.Errorf("stat dir %+v %v", d, err)
			}
			// follow describes an object that is no reparse point itself.
			if f, err := b.Stat(ctx, dir+"/sub/a.txt", true); err != nil || f.Path != e.Path || f.Size != 11 {
				t.Errorf("stat follow %+v %v", f, err)
			}
			if got := names(t, b, dir+"/sub"); !slices.Equal(got, []string{"a.txt"}) {
				t.Errorf("listing %v", got)
			}
			r, err := b.Open(ctx, dir+"/sub/a.txt", files.Range{Offset: 6, Length: 3})
			if err != nil {
				t.Fatal(err)
			}
			part, _ := io.ReadAll(r)
			_ = r.Close()
			if string(part) != "wor" {
				t.Errorf("range read %q", part)
			}
			_, err = b.Open(ctx, dir+"/sub", files.Range{Length: -1})
			wantCode(t, err, fault.UnsupportedOperation)
			writeFile(t, b, dir+"/sub/b.txt", "b", files.WriteOptions{Exclusive: true})
			wantCode(t, b.Rename(ctx, dir+"/sub/a.txt", dir+"/sub/b.txt"), fault.FileConflict)
			if err := b.Rename(ctx, dir+"/sub/a.txt", dir+"/c.txt"); err != nil {
				t.Fatal(err)
			}
			if readFile(t, b, dir+"/c.txt") != "hello world" {
				t.Error("renamed content")
			}
			wantCode(t, b.Remove(ctx, dir+"/sub", false, files.Budget{}), fault.FileConflict)
			wantCode(t, b.Remove(ctx, "/", true, files.Budget{}), fault.InvalidRequest)
			wantCode(t, b.Chmod(ctx, dir+"/c.txt", 0o600), fault.UnsupportedOperation)
			var walked []string
			if err := b.Walk(ctx, dir, files.Budget{}, func(e files.Entry) error { walked = append(walked, e.Path); return nil }); err != nil {
				t.Fatal(err)
			}
			slices.Sort(walked)
			want := []string{dir, dir + "/c.txt", dir + "/sub", dir + "/sub/b.txt"}
			if !slices.Equal(walked, want) {
				t.Errorf("walk %v", walked)
			}
			wantCode(t, b.Walk(ctx, dir, files.Budget{MaxMembers: 2}, func(files.Entry) error { return nil }), fault.LimitExceeded)
			wantCode(t, b.Remove(ctx, dir+"/sub", true, files.Budget{MaxMembers: 1}), fault.LimitExceeded)
			if err := b.Remove(ctx, dir+"/sub", true, files.Budget{}); err != nil {
				t.Fatal(err)
			}
			if got := names(t, b, dir); !slices.Equal(got, []string{"c.txt"}) {
				t.Errorf("after remove %v", got)
			}
		})
	}
}

func TestLabRemoveReadOnly(t *testing.T) {
	for _, tg := range labTargets(t) {
		t.Run(tg.name, func(t *testing.T) {
			ctx := t.Context()
			b := connectLab(t, tg, nil)
			dir := labDir(t, b)
			writeFile(t, b, dir+"/ro.txt", "ro", files.WriteOptions{Exclusive: true})
			o, err := b.leaf(ctx, []string{dir[1:], "ro.txt"}, nil, accessDeleteReadOnly, fileOpen, shareAll, kindFile)
			if err != nil {
				t.Fatal(err)
			}
			err = o.setAttributes(ctx, attrReadOnly)
			o.release()
			if err != nil {
				t.Fatal(err)
			}
			if e, _ := b.Stat(ctx, dir+"/ro.txt", false); e.Mode != 0o100444 {
				t.Errorf("mode %o", e.Mode)
			}
			if err := b.Remove(ctx, dir+"/ro.txt", false, files.Budget{}); err != nil {
				t.Fatal(err)
			}
			if got := names(t, b, dir); len(got) != 0 {
				t.Errorf("left %v", got)
			}
		})
	}
}

// TestLabAtomicReplace: replacing a file installs the new content in one
// step and no failure loses the old content.
func TestLabAtomicReplace(t *testing.T) {
	for _, tg := range labTargets(t) {
		t.Run(tg.name, func(t *testing.T) {
			ctx := t.Context()
			b := connectLab(t, tg, nil)
			dir := labDir(t, b)
			target := dir + "/data.bin"
			versions := [][]byte{bytes.Repeat([]byte("A"), 3<<20+17), bytes.Repeat([]byte("B"), 2<<20+5), bytes.Repeat([]byte("C"), 4<<20)}
			if _, err := b.Write(ctx, target, bytes.NewReader(versions[0]), files.WriteOptions{Exclusive: true, Size: int64(len(versions[0]))}); err != nil {
				t.Fatal(err)
			}
			// A reader in a second session sees one whole version at every
			// moment while the file is replaced again and again.
			other := connectLab(t, tg, nil)
			stop := make(chan struct{})
			var wg sync.WaitGroup
			var torn, reads int
			wg.Go(func() {
				for {
					select {
					case <-stop:
						return
					default:
					}
					r, err := other.Open(ctx, target, files.Range{Length: -1})
					if err != nil {
						continue // the name is briefly being swapped
					}
					data, err := io.ReadAll(r)
					_ = r.Close()
					if err != nil {
						continue
					}
					reads++
					if !slices.ContainsFunc(versions, func(v []byte) bool { return bytes.Equal(v, data) }) {
						torn++
					}
				}
			})
			// A replace while the reader holds the file open is refused by
			// the server (the name cannot be taken over), never done in
			// place: ATOMIC_REPLACE_UNAVAILABLE, the old file intact.
			replaced, refused := 0, 0
			for i := range 12 {
				v := versions[(i+1)%len(versions)]
				res, err := b.Write(ctx, target, bytes.NewReader(v), files.WriteOptions{Size: int64(len(v))})
				switch fault.CodeOf(err) {
				case "":
					replaced++
					if res.Size != int64(len(v)) {
						t.Errorf("size %d", res.Size)
					}
				case fault.AtomicReplaceUnavailable:
					refused++
				default:
					t.Fatalf("replace %d: %v", i, err)
				}
			}
			close(stop)
			wg.Wait()
			if torn != 0 || reads == 0 {
				t.Errorf("reads %d, torn %d", reads, torn)
			}
			t.Logf("concurrent reads %d, replaced %d, refused while open %d", reads, replaced, refused)
			last := versions[2]
			if _, err := b.Write(ctx, target, bytes.NewReader(last), files.WriteOptions{Size: int64(len(last))}); err != nil {
				t.Fatal(err)
			}
			if readFile(t, b, target) != string(last) {
				t.Fatal("final content")
			}
			// Failures before the rename leave the target untouched and
			// remove the temporary file.
			_, err := b.Write(ctx, target, &failingReader{n: 3 << 20}, files.WriteOptions{Size: -1})
			wantCode(t, err, fault.SourceChanged)
			_, err = b.Write(ctx, target, strings.NewReader("short"), files.WriteOptions{Size: 100})
			wantCode(t, err, fault.SourceChanged)
			_, err = b.Write(ctx, target, strings.NewReader("too long"), files.WriteOptions{Size: -1, MaxBytes: 3})
			wantCode(t, err, fault.LimitExceeded)
			cctx, cancel := context.WithCancel(ctx)
			cancel()
			_, err = b.Write(cctx, target, strings.NewReader("cancelled"), files.WriteOptions{Size: -1})
			if err == nil {
				t.Fatal("cancelled write succeeded")
			}
			if readFile(t, b, target) != string(last) {
				t.Fatal("a failed replace changed the target")
			}
			if got := names(t, b, dir); !slices.Equal(got, []string{"data.bin"}) {
				t.Errorf("leftovers %v", got)
			}
			// A directory is never replaced by a file.
			if err := b.Mkdir(ctx, dir+"/d"); err != nil {
				t.Fatal(err)
			}
			_, err = b.Write(ctx, dir+"/d", strings.NewReader("x"), files.WriteOptions{Size: 1})
			wantCode(t, err, fault.FileConflict)
		})
	}
}

func TestLabReadOnlyShare(t *testing.T) {
	for _, tg := range labTargets(t) {
		if tg.readerUser == "" {
			continue
		}
		t.Run(tg.name, func(t *testing.T) {
			ctx := t.Context()
			ro := tg
			ro.share, ro.user, ro.password = "ReadOnly", tg.readerUser, tg.readerPassword
			b := connectLab(t, ro, nil)
			if a := b.RootAccess(); a.List != files.AccessGranted || a.CreateFile == files.AccessGranted {
				t.Errorf("read-only access %+v", a)
			}
			_, err := b.Write(ctx, "/fs3-denied.txt", strings.NewReader("x"), files.WriteOptions{Exclusive: true, Size: 1})
			wantCode(t, err, fault.FilePermissionDenied)
			wantCode(t, b.Mkdir(ctx, "/fs3-denied"), fault.FilePermissionDenied)
			// The reader has no access to the writable shares at all.
			denied := ro
			denied.share = "Secure"
			_, err = Connect(ctx, labConfig(t, tg.port, nil), denied.target())
			if c := fault.CodeOf(err); c != fault.FilePermissionDenied && c != fault.ShareUnavailable {
				t.Errorf("reader on Secure: %v", err)
			}
		})
	}
}
