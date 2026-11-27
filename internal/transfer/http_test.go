package transfer_test

import (
	"archive/zip"
	"bytes"
	json "encoding/json/v2"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/transfer"
)

func failureBody(t *testing.T, r response) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(r.Body.Bytes(), &out); err != nil {
		t.Fatalf("body %q: %v", r.Body.String(), err)
	}
	return out
}

func TestDownloadStreamsTheFileOnce(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	data := bytes.Repeat([]byte("abcdefgh"), 20000)
	e.a.PutFile("/srv/Ünïcode report.txt", data)
	pr := e.prepare(transfer.PrepareRequest{SourceID: "sftp-session:a", Direction: transfer.Download, Path: "/srv/Ünïcode report.txt"})
	if !strings.HasPrefix(pr.URL, "/root/api/transfers/") || !strings.HasSuffix(pr.URL, "/download") {
		t.Fatalf("url %q", pr.URL)
	}
	if e.src.holds() != 1 {
		t.Fatal("a prepared download holds its source")
	}
	got := e.do(e.owner, http.MethodGet, pr.URL, nil, 0)
	if got.Code != 200 || !bytes.Equal(got.Body.Bytes(), data) {
		t.Fatalf("status %d, %d bytes", got.Code, got.Body.Len())
	}
	h := got.Header()
	if h.Get("Content-Length") != "160000" || h.Get("Cache-Control") != "no-store" || h.Get("Accept-Ranges") != "none" ||
		h.Get("Content-Disposition") != `attachment; filename="ncode report.txt"; filename*=UTF-8''%C3%9Cn%C3%AFcode%20report.txt` {
		t.Fatalf("headers %v", h)
	}
	if ev := e.ev.wait(t, pr.TransferID); ev.State != transfer.Completed || ev.Direction != transfer.Download {
		t.Fatalf("finished %+v", ev)
	}
	e.idle()
	if again := e.do(e.owner, http.MethodGet, pr.URL, nil, 0); again.Code != 404 || again.Body.Len() != 0 {
		t.Fatalf("second use: %d %q", again.Code, again.Body.String())
	}
	if st := e.m.CancelFor(e.owner.UserID, pr.TransferID); st != transfer.Completed {
		t.Fatalf("late cancel %s", st)
	}
	e.ev.mu.Lock()
	last := e.ev.progress[len(e.ev.progress)-1]
	e.ev.mu.Unlock()
	if last.Transferred != int64(len(data)) || last.Total != int64(len(data)) {
		t.Fatalf("last progress %+v", last)
	}
}

func TestTokenIsBoundToUserSessionAndRoute(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.a.PutFile("/f", []byte("x"))
	pr := e.prepare(transfer.PrepareRequest{SourceID: "sftp-session:a", Direction: transfer.Download, Path: "/f"})
	other := principaltest.User(8)
	sameUserOtherSession := e.owner
	sameUserOtherSession.SessionID = "elsewhere"
	for _, p := range []struct {
		name string
		resp response
	}{
		{"other user", e.do(other, http.MethodGet, pr.URL, nil, 0)},
		{"other session", e.do(sameUserOtherSession, http.MethodGet, pr.URL, nil, 0)},
		{"malformed", e.do(e.owner, http.MethodGet, "/api/transfers/short/download", nil, 0)},
		{"head", e.do(e.owner, http.MethodHead, pr.URL, nil, 0)},
	} {
		if p.resp.Code != 404 || p.resp.Body.Len() != 0 {
			t.Errorf("%s: %d %q", p.name, p.resp.Code, p.resp.Body.String())
		}
	}
	// Still usable by its owner after the refusals.
	folderURL := strings.Replace(pr.URL, "/download", "/folder-download", 1)
	if r := e.do(e.owner, http.MethodGet, folderURL, nil, 0); r.Code != 404 {
		t.Fatalf("misdirected: %d", r.Code)
	}
	// The misdirected use spent the token.
	if r := e.do(e.owner, http.MethodGet, pr.URL, nil, 0); r.Code != 404 {
		t.Fatalf("after misdirection: %d", r.Code)
	}
	e.idle()
}

func TestPreparedTokenExpires(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(o *transfer.Options) { o.TokenTTL = 30 * time.Millisecond })
	e.a.PutFile("/f", []byte("x"))
	pr := e.prepare(transfer.PrepareRequest{SourceID: "sftp-session:a", Direction: transfer.Download, Path: "/f"})
	e.idle()
	if r := e.do(e.owner, http.MethodGet, pr.URL, nil, 0); r.Code != 404 {
		t.Fatalf("expired token: %d", r.Code)
	}
}

func TestPrepareRefusals(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, rq := range []transfer.PrepareRequest{
		{SourceID: "sftp-session:a", Direction: "sideways", Path: "/f"},
		{SourceID: "sftp-session:a", Direction: transfer.Download, Path: "/f", Policy: transfer.ConflictReplace},
		{SourceID: "sftp-session:a", Direction: transfer.Upload, Path: "/f", Policy: "merge"},
		{SourceID: "sftp-session:a", Direction: transfer.Upload, Path: "/"},
		{SourceID: "sftp-session:a", Direction: transfer.Download, Path: "relative"},
		{SourceID: "sftp-session:a", Direction: transfer.Download, Path: "/a/../b"},
		{SourceID: "sftp-session:x", Direction: transfer.Download, Path: "/f"},
	} {
		if _, err := e.m.Prepare(t.Context(), e.caller(), rq); !fault.Is(err, fault.TransferUnavailable) {
			t.Errorf("%+v: %v", rq, err)
		}
	}
	// Quota: two per user.
	for range 2 {
		e.prepare(transfer.PrepareRequest{SourceID: "sftp-session:a", Direction: transfer.Download, Path: "/f"})
	}
	if _, err := e.m.Prepare(t.Context(), e.caller(), transfer.PrepareRequest{SourceID: "sftp-session:a", Direction: transfer.Download, Path: "/f"}); err == nil {
		t.Fatal("third transfer accepted")
	}
	if e.src.holds() != 2 {
		t.Fatalf("a refused transfer keeps its hold: %d", e.src.holds())
	}
}

func TestDownloadLimitAndMissingFile(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(o *transfer.Options) { o.Limits = transfer.DefaultLimits; o.Limits.MaxDownload = 10 })
	e.a.PutFile("/big", make([]byte, 11))
	e.a.PutFile("/dir/x", nil)
	pr := e.prepare(transfer.PrepareRequest{SourceID: "sftp-session:a", Direction: transfer.Download, Path: "/big"})
	r := e.do(e.owner, http.MethodGet, pr.URL, nil, 0)
	got := failureBody(t, r)
	if r.Code != 413 || got["error_code"] != "LIMIT_EXCEEDED" || got["limit_kind"] != "download" || got["limit_bytes"] != 10.0 || got["actual_bytes"] != 11.0 {
		t.Fatalf("%d %v", r.Code, got)
	}
	if ev := e.ev.wait(t, pr.TransferID); ev.State != transfer.Failed || ev.Failure.LimitKind != transfer.LimitDownload {
		t.Fatalf("finished %+v", ev)
	}
	pr = e.prepare(transfer.PrepareRequest{SourceID: "sftp-session:a", Direction: transfer.Download, Path: "/dir"})
	r = e.do(e.owner, http.MethodGet, pr.URL, nil, 0)
	if got := failureBody(t, r); r.Code != 404 || got["error_code"] != "NOT_FOUND" || got["retryable"] != false {
		t.Fatalf("folder as file: %d %v", r.Code, got)
	}
	e.idle()
}

func TestUploadConflictReplaceAndLimits(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(o *transfer.Options) { o.Limits = transfer.DefaultLimits; o.Limits.MaxUpload = 100 })
	e.b.PutFile("/up.txt", []byte("old"))
	upload := func(policy transfer.ConflictPolicy, data []byte, size int64) response {
		pr := e.prepare(transfer.PrepareRequest{SourceID: "smb-quick:b", Direction: transfer.Upload, Path: "/up.txt", Policy: policy})
		if !strings.HasSuffix(pr.URL, "/upload") {
			t.Fatalf("url %q", pr.URL)
		}
		return e.do(e.owner, http.MethodPost, pr.URL, body(data), size)
	}
	r := upload("", []byte("new"), 3)
	if got := failureBody(t, r); r.Code != 409 || got["error_code"] != "CONFLICT" || got["error"] != "A file or folder already exists at the destination." {
		t.Fatalf("conflict: %d %v", r.Code, got)
	}
	if r := upload(transfer.ConflictReplace, []byte("new"), 3); r.Code != 200 || r.Body.String() != `{"success":true}` {
		t.Fatalf("replace: %d %q", r.Code, r.Body.String())
	}
	if got, _ := e.b.File("/up.txt"); string(got) != "new" {
		t.Fatalf("content %q", got)
	}
	r = upload(transfer.ConflictReplace, make([]byte, 101), 101)
	if got := failureBody(t, r); r.Code != 413 || got["limit_kind"] != "upload" || got["actual_bytes"] != 101.0 {
		t.Fatalf("too large: %d %v", r.Code, got)
	}
	r = upload(transfer.ConflictReplace, []byte("x"), -1)
	if got := failureBody(t, r); r.Code != 413 || got["limit_kind"] != "upload" || got["actual_bytes"] != nil {
		t.Fatalf("no length: %d %v", r.Code, got)
	}
	// A body shorter than its length installs nothing.
	r = upload(transfer.ConflictReplace, []byte("xy"), 5)
	if r.Code == 200 {
		t.Fatal("short body accepted")
	}
	if got, _ := e.b.File("/up.txt"); string(got) != "new" {
		t.Fatalf("content after a short body %q", got)
	}
	e.idle()
}

func TestFolderDownloadIsAZipOfTheTree(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.a.PutFile("/srv/site/index.html", []byte("<h1>"))
	e.a.PutFile("/srv/site/img/a.png", bytes.Repeat([]byte{1}, 5000))
	e.a.PutFile(`/srv/site/odd\name`, []byte("x"))
	pr := e.prepare(transfer.PrepareRequest{SourceID: "sftp-session:a", Direction: transfer.Download, Path: "/srv/site", Archive: true})
	if !strings.HasSuffix(pr.URL, "/folder-download") {
		t.Fatalf("url %q", pr.URL)
	}
	r := e.do(e.owner, http.MethodGet, pr.URL, nil, 0)
	if r.Code != 200 || r.aborted || r.Header().Get("Content-Type") != "application/zip" ||
		!strings.Contains(r.Header().Get("Content-Disposition"), `filename="site.zip"`) {
		t.Fatalf("%d %v aborted=%v", r.Code, r.Header(), r.aborted)
	}
	zr, err := zip.NewReader(bytes.NewReader(r.Body.Bytes()), int64(r.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		n, _ := io.Copy(io.Discard, rc)
		rc.Close()
		got[f.Name] = int(n)
	}
	want := map[string]int{"site/index.html": 4, "site/img/": 0, "site/img/a.png": 5000, "site/odd_name": 1}
	if len(got) != len(want) {
		t.Fatalf("members %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("members %v", got)
		}
	}
	if ev := e.ev.wait(t, pr.TransferID); ev.State != transfer.Completed {
		t.Fatalf("finished %+v", ev)
	}
	e.idle()
}

func TestFolderDownloadRefusesBeforeSending(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(o *transfer.Options) {
		o.Limits = transfer.DefaultLimits
		o.Limits.MaxArchive, o.Limits.MaxMembers = 100, 3
	})
	e.a.PutFile("/link/f", nil)
	e.a.PutLink("/link/l", "/etc")
	e.a.PutFile("/big/f", make([]byte, 101))
	e.a.PutFile("/many/1", nil)
	e.a.PutFile("/many/2", nil)
	e.a.PutFile("/many/3", nil)
	e.a.PutFile("/many/4", nil)
	e.a.PutFile("/file", nil)
	for _, c := range []struct {
		path, code string
		status     int
	}{
		{"/link", "TRANSFER_UNAVAILABLE", 500}, {"/big", "LIMIT_EXCEEDED", 413}, {"/many", "LIMIT_EXCEEDED", 413},
		{"/file", "NOT_FOUND", 404}, {"/missing", "NOT_FOUND", 404},
	} {
		pr := e.prepare(transfer.PrepareRequest{SourceID: "sftp-session:a", Direction: transfer.Download, Path: c.path, Archive: true})
		r := e.do(e.owner, http.MethodGet, pr.URL, nil, 0)
		if got := failureBody(t, r); r.Code != c.status || got["error_code"] != c.code {
			t.Errorf("%s: %d %v", c.path, r.Code, got)
		}
	}
	e.idle()
}

func TestArchiveLimitFollowsTheTempQuota(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(o *transfer.Options) { o.Limits = transfer.DefaultLimits; o.Limits.TempBytesPerUse = 3 })
	e.a.PutFile("/d/f", []byte("four"))
	pr := e.prepare(transfer.PrepareRequest{SourceID: "sftp-session:a", Direction: transfer.Download, Path: "/d", Archive: true})
	if r := e.do(e.owner, http.MethodGet, pr.URL, nil, 0); r.Code != 413 {
		t.Fatalf("%d", r.Code)
	}
	e.idle()
}

func TestContentDisposition(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for name, want := range map[string]string{
		"plain.txt": `attachment; filename="plain.txt"; filename*=UTF-8''plain.txt`,
		`a"b;c.txt`: `attachment; filename="a_b_c.txt"; filename*=UTF-8''a%22b%3Bc.txt`,
		"日本.txt":    `attachment; filename=".txt"; filename*=UTF-8''%E6%97%A5%E6%9C%AC.txt`,
		"日本":        `attachment; filename="download"; filename*=UTF-8''%E6%97%A5%E6%9C%AC`,
		"x~y-z":     `attachment; filename="x_y-z"; filename*=UTF-8''x~y-z`,
	} {
		e.a.PutFile("/"+name, []byte("x"))
		pr := e.prepare(transfer.PrepareRequest{SourceID: "sftp-session:a", Direction: transfer.Download, Path: "/" + name})
		if got := e.do(e.owner, http.MethodGet, pr.URL, nil, 0).Header().Get("Content-Disposition"); got != want {
			t.Errorf("%q: %s, want %s", name, got, want)
		}
		e.idle()
	}
}

// TR1-2: a streamed ZIP uses no disk and charges no temp_bytes quota; the
// quota only caps one archive.
func TestArchiveChargesNoTempQuota(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.quota.mu.Lock()
	e.quota.limit["temp_bytes"] = 0
	e.quota.mu.Unlock()
	e.a.PutFile("/d/f", []byte("four"))
	pr := e.prepare(transfer.PrepareRequest{SourceID: "sftp-session:a", Direction: transfer.Download, Path: "/d", Archive: true})
	if r := e.do(e.owner, http.MethodGet, pr.URL, nil, 0); r.Code != http.StatusOK {
		t.Fatalf("%d", r.Code)
	}
	e.idle()
}
