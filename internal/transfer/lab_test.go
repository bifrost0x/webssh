//go:build lab

// The lab tests run transfers through the real SFTP backend against
// ssh-modern and the real SMB backend against Samba (tests/lab):
//
//	WEBSSH_LAB_JSON=…/tests/lab/runtime/lab.json go test -tags lab -run Lab -v ./internal/transfer
//
// They fail, not skip, when the lab is not reachable, and work in fresh
// directories that they remove afterwards.
package transfer_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	json "encoding/json/v2"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/files/sftp"
	"github.com/bifrost0x/webssh/internal/files/smb"
	"github.com/bifrost0x/webssh/internal/netpolicy"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/ssh/hostkey"
	"github.com/bifrost0x/webssh/internal/store/storetest"
	"github.com/bifrost0x/webssh/internal/transfer"
)

type labService struct {
	Host         string            `json:"host"`
	Port         int               `json:"port"`
	Fingerprints map[string]string `json:"host_key_fingerprints"`
}

type labFile struct {
	RuntimeDir string                `json:"runtime_dir"`
	Services   map[string]labService `json:"services"`
}

var loadLab = sync.OnceValues(func() (labFile, error) {
	p := os.Getenv("WEBSSH_LAB_JSON")
	if p == "" {
		p = filepath.Join("..", "..", "tests", "lab", "runtime", "lab.json")
	}
	var l labFile
	raw, err := os.ReadFile(p)
	if err != nil {
		return l, err
	}
	return l, json.Unmarshal(raw, &l, json.RejectUnknownMembers(false))
})

func lab(t testing.TB) labFile {
	t.Helper()
	l, err := loadLab()
	if err != nil {
		t.Fatalf("lab not available (set WEBSSH_LAB_JSON): %v", err)
	}
	return l
}

func labSecret(t testing.TB, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(lab(t).RuntimeDir, rel))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(raw))
}

// knownKeys accepts the host key the lab published.
type knownKeys struct{ fps []string }

func (k knownKeys) HostKey(_ context.Context, q client.HostKeyPrompt) (bool, error) {
	return slices.Contains(k.fps, q.Fingerprint), nil
}
func (knownKeys) Banner(context.Context, client.BannerPrompt) (bool, error) { return true, nil }

func openSFTP(t *testing.T) files.Backend {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	policy, err := netpolicy.New(netpolicy.Config{Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	q := &sftp.Quick{Dialer: &client.Dialer{Net: policy, HostKeys: hostkey.New(storetest.Open(t, hostkey.Schema()), logger)}}
	s := lab(t).Services["ssh-modern"]
	var fps []string
	for _, fp := range s.Fingerprints {
		fps = append(fps, fp)
	}
	tgt := client.Target{Hop: client.Hop{Host: s.Host, Port: s.Port, User: "pwuser", Auth: client.Auth{Password: labSecret(t, "secrets/ssh-pwuser")}}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, b, err := q.Open(ctx, principal.Principal{UserID: 1, SessionID: "s"}, tgt, knownKeys{fps})
	if err != nil {
		t.Fatalf("quick sftp: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func openSMB(t *testing.T) files.Backend {
	t.Helper()
	policy, err := netpolicy.New(netpolicy.Config{})
	if err != nil {
		t.Fatal(err)
	}
	s := lab(t).Services["samba"]
	cfg := smb.Config{Network: policy, AllowedTargets: []string{"127.0.0.1"}, ConnectTimeout: 15 * time.Second,
		IOIdleTimeout: 15 * time.Second, Port: uint16(s.Port)} // #nosec G115 -- lab port
	b, err := smb.Connect(t.Context(), cfg, smb.Target{Host: "127.0.0.1", Share: "Secure", Domain: "LAB", Username: "smbuser",
		Password: []byte(labSecret(t, "secrets/samba-smbuser"))})
	if err != nil {
		t.Fatalf("smb connect: %v (%+v)", err, smb.DiagnosticOf(err))
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

// workdir creates a fresh directory on b and removes it afterwards.
func workdir(t *testing.T, b files.Backend) string {
	t.Helper()
	home, err := b.Home(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var tag [6]byte
	_, _ = rand.Read(tag[:])
	dir := strings.TrimSuffix(home, "/") + fmt.Sprintf("/tr1-lab-%x", tag)
	if err := b.Mkdir(t.Context(), dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Remove(context.Background(), dir, true, files.Budget{MaxMembers: 100000}) })
	return dir
}

func labWrite(t *testing.T, b files.Backend, p string, data []byte) {
	t.Helper()
	if _, err := b.Write(t.Context(), p, bytes.NewReader(data), files.WriteOptions{Exclusive: true, Size: int64(len(data))}); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
}

func labHash(t *testing.T, b files.Backend, p string) [32]byte {
	t.Helper()
	rd, err := b.Open(t.Context(), p, files.Range{Length: -1})
	if err != nil {
		t.Fatalf("open %s: %v", p, err)
	}
	defer rd.Close()
	h := sha256.New()
	if _, err := io.Copy(h, rd); err != nil {
		t.Fatal(err)
	}
	return [32]byte(h.Sum(nil))
}

func labNames(t *testing.T, b files.Backend, dir string) []string {
	t.Helper()
	l, err := b.OpenListing(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var out []string
	for {
		page, more, err := l.Next(t.Context(), 500)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range page {
			out = append(out, e.Name)
		}
		if !more {
			slices.Sort(out)
			return out
		}
	}
}

func random(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// labEnv is a manager whose sources are the real backends.
func labEnv(t *testing.T, limits transfer.Limits) (*env, map[string]files.Backend) {
	e := newEnv(t, func(o *transfer.Options) { o.Limits = limits })
	backends := map[string]files.Backend{"sftp-quick:lab": openSFTP(t), "smb-quick:lab": openSMB(t)}
	for id, b := range backends {
		e.src.add(id, e.owner, b)
	}
	return e, backends
}

func TestLabCopyBetweenEveryKind(t *testing.T) {
	e, backends := labEnv(t, transfer.DefaultLimits)
	dirs := map[string]string{}
	for id, b := range backends {
		dirs[id] = workdir(t, b)
	}
	big, small := random(20<<20+3), random(1000)
	for id, b := range backends {
		labWrite(t, b, dirs[id]+"/big.bin", big)
		if err := b.Mkdir(t.Context(), dirs[id]+"/tree"); err != nil {
			t.Fatal(err)
		}
		if err := b.Mkdir(t.Context(), dirs[id]+"/tree/sub"); err != nil {
			t.Fatal(err)
		}
		labWrite(t, b, dirs[id]+"/tree/sub/small.txt", small)
	}
	ids := slices.Sorted(func(yield func(string) bool) {
		for id := range backends {
			if !yield(id) {
				return
			}
		}
	})
	for _, from := range ids {
		for _, to := range ids {
			name := strings.SplitN(from, "-", 2)[0] + "-to-" + strings.SplitN(to, "-", 2)[0]
			t.Run(name, func(t *testing.T) {
				dst := dirs[to] + "/" + name
				copyOK := func(src, dstPath string, policy transfer.ConflictPolicy) transfer.Finished {
					id, err := e.m.Copy(t.Context(), e.caller(), transfer.CopyRequest{SourceID: from, SourcePath: src, DestID: to,
						DestPath: dstPath, RequestID: "lab", Policy: policy})
					if err != nil {
						t.Fatal(err)
					}
					return e.ev.wait(t, id)
				}
				if ev := copyOK(dirs[from]+"/big.bin", dst+".bin", ""); ev.State != transfer.Completed {
					t.Fatalf("file: %+v %+v", ev, ev.Failure)
				}
				if labHash(t, backends[to], dst+".bin") != sha256.Sum256(big) {
					t.Fatal("copied file differs")
				}
				if ev := copyOK(dirs[from]+"/big.bin", dst+".bin", ""); ev.Failure == nil || ev.Failure.Code != "CONFLICT" {
					t.Fatalf("conflict: %+v", ev)
				}
				if ev := copyOK(dirs[from]+"/tree/sub/small.txt", dst+".bin", transfer.ConflictReplace); ev.State != transfer.Completed {
					t.Fatalf("replace: %+v %+v", ev, ev.Failure)
				}
				if labHash(t, backends[to], dst+".bin") != sha256.Sum256(small) {
					t.Fatal("replaced file differs")
				}
				if ev := copyOK(dirs[from]+"/tree", dst, ""); ev.State != transfer.Completed {
					t.Fatalf("tree: %+v %+v", ev, ev.Failure)
				}
				if labHash(t, backends[to], dst+"/sub/small.txt") != sha256.Sum256(small) {
					t.Fatal("copied tree differs")
				}
				if from == to {
					if ev := copyOK(dirs[from]+"/tree", dirs[from]+"/tree", ""); ev.Failure == nil || ev.Failure.Code != "CONFLICT" {
						t.Fatalf("same path: %+v", ev)
					}
				}
				e.idle()
			})
		}
	}
}

// TestLabLargeUploadAndDownload streams 200 MiB into each backend and
// back while sampling the heap, and downloads a folder as ZIP.
func TestLabLargeUploadAndDownload(t *testing.T) {
	const size = 200 << 20
	limits := transfer.DefaultLimits
	limits.MaxUpload, limits.MaxDownload = size, size
	e, backends := labEnv(t, limits)
	for id, b := range backends {
		t.Run(strings.SplitN(id, "-", 2)[0], func(t *testing.T) {
			dir := workdir(t, b)
			src := newStream(size)
			pr := e.prepare(transfer.PrepareRequest{SourceID: id, Direction: transfer.Upload, Path: dir + "/large.bin"})
			var r response
			start := time.Now()
			up := heapWatch(t, func() {
				r = e.do(e.owner, http.MethodPost, pr.URL, &genReader{b: src, ctx: t.Context()}, size)
			})
			if r.Code != 200 {
				t.Fatalf("upload %d %s", r.Code, r.Body.String())
			}
			upTime := time.Since(start)
			pr = e.prepare(transfer.PrepareRequest{SourceID: id, Direction: transfer.Download, Path: dir + "/large.bin"})
			out := &hashWriter{h: sha256.New(), hdr: http.Header{}}
			start = time.Now()
			down := heapWatch(t, func() {
				req, _ := http.NewRequestWithContext(principal.With(t.Context(), e.owner), http.MethodGet, strings.TrimPrefix(pr.URL, "/root"), nil)
				e.mux.ServeHTTP(out, req)
			})
			downTime := time.Since(start)
			want := sha256.New()
			_, _ = io.Copy(want, &genReader{b: newStream(size), ctx: t.Context()})
			if out.n != size || !bytes.Equal(out.h.Sum(nil), want.Sum(nil)) {
				t.Fatalf("downloaded %d bytes, hash differs", out.n)
			}
			t.Logf("200 MiB: upload %v (heap +%d KiB), download %v (heap +%d KiB)", upTime.Round(time.Millisecond), up>>10,
				downTime.Round(time.Millisecond), down>>10)
			if up > 32<<20 || down > 32<<20 {
				t.Fatalf("heap grew by %d / %d bytes", up, down)
			}

			if err := b.Mkdir(t.Context(), dir+"/folder"); err != nil {
				t.Fatal(err)
			}
			labWrite(t, b, dir+"/folder/a.txt", []byte("alpha"))
			pr = e.prepare(transfer.PrepareRequest{SourceID: id, Direction: transfer.Download, Path: dir + "/folder", Archive: true})
			if r := e.do(e.owner, http.MethodGet, pr.URL, nil, 0); r.Code != 200 || r.aborted || !bytes.Contains(r.Body.Bytes(), []byte("folder/a.txt")) {
				t.Fatalf("zip %d aborted=%v", r.Code, r.aborted)
			}
			e.idle()
		})
	}
}

// TestLabCancelledUploadLeavesNothing cancels an upload mid-body and a
// copy mid-file: the target does not exist and no staging file is left
// in the directory (E38).
func TestLabCancelledUploadLeavesNothing(t *testing.T) {
	e, backends := labEnv(t, transfer.DefaultLimits)
	for id, b := range backends {
		t.Run(strings.SplitN(id, "-", 2)[0], func(t *testing.T) {
			dir := workdir(t, b)
			pr := e.prepare(transfer.PrepareRequest{SourceID: id, Direction: transfer.Upload, Path: dir + "/partial.bin"})
			body, w := io.Pipe()
			done := make(chan response, 1)
			go func() { done <- e.do(e.owner, http.MethodPost, pr.URL, body, 50<<20) }()
			if _, err := w.Write(random(4 << 20)); err != nil {
				t.Fatal(err)
			}
			if st := e.m.CancelFor(e.owner.UserID, pr.TransferID); st != transfer.Cancelling {
				t.Fatalf("cancel %s", st)
			}
			go func() { _, _ = w.Write(random(1 << 20)) }()
			r := <-done
			_ = w.Close()
			if got := failureBody(t, r); got["error_code"] != "CANCELLED" {
				t.Fatalf("%d %v", r.Code, got)
			}
			if names := labNames(t, b, dir); len(names) != 0 {
				t.Fatalf("left behind: %v", names)
			}

			// A copy from a slow source, cancelled mid-file.
			s := newStream(8 << 20)
			s.gate = make(chan struct{})
			e.src.add("sftp-quick:slow", e.owner, s)
			cid, err := e.m.Copy(t.Context(), e.caller(), transfer.CopyRequest{SourceID: "sftp-quick:slow", SourcePath: "/gen", DestID: id,
				DestPath: dir + "/copy.bin", RequestID: "lab"})
			if err != nil {
				t.Fatal(err)
			}
			for range 20 {
				s.gate <- struct{}{}
			}
			e.m.CancelFor(e.owner.UserID, cid)
			if ev := e.ev.wait(t, cid); ev.State != transfer.Cancelled {
				t.Fatalf("copy %+v %+v", ev, ev.Failure)
			}
			if names := labNames(t, b, dir); len(names) != 0 {
				t.Fatalf("copy left behind: %v", names)
			}
			e.idle()
		})
	}
}

type hashWriter struct {
	h   hash.Hash
	hdr http.Header
	n   int64
}

func (w *hashWriter) Header() http.Header { return w.hdr }
func (w *hashWriter) WriteHeader(int)     {}
func (w *hashWriter) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	return w.h.Write(p)
}
