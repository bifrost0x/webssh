package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// webssh starts the test binary as `webssh args...` in its own process.
func webssh(t *testing.T, env []string, args ...string) *exec.Cmd {
	t.Helper()
	raw, _ := json.Marshal(args)
	cmd := exec.CommandContext(t.Context(), os.Args[0])
	cmd.Env = append(append(os.Environ(), env...), envProcessArgs+"="+string(raw))
	cmd.Env = append(cmd.Env, helperTempDir(t)...)
	return cmd
}

func freePort(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return port
}

var csrfField = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

// signUp creates the first administrator through the browser bootstrap
// and returns the client with its session cookie.
func signUp(t *testing.T, base, user, password string) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	resp, err := c.Get(base + "/register")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := csrfField.FindSubmatch(body)
	if m == nil {
		t.Fatalf("no CSRF token on /register (%d)", resp.StatusCode)
	}
	form := url.Values{"username": {user}, "password": {password}, "confirm_password": {password}, "csrf_token": {string(m[1])}}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", base)
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	u, _ := url.Parse(base)
	for _, ck := range jar.Cookies(u) {
		if ck.Name == "session" && ck.Value != "" {
			return c
		}
	}
	t.Fatalf("registration gave no session (%d %s)", resp.StatusCode, resp.Request.URL.Path)
	return nil
}

// openRealtime upgrades to /ws with the client's session and returns the
// connection after the server's first frame (hello).
func openRealtime(t *testing.T, c *http.Client, base string) (net.Conn, *bufio.Reader) {
	t.Helper()
	u, _ := url.Parse(base)
	var cookies []string
	for _, ck := range c.Jar.Cookies(u) {
		cookies = append(cookies, ck.Name+"="+ck.Value)
	}
	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"+
		"Sec-WebSocket-Key: %s\r\nSec-WebSocket-Protocol: webssh.v1\r\nOrigin: %s\r\nCookie: %s\r\n\r\n",
		u.Host, base64.StdEncoding.EncodeToString(key), base, strings.Join(cookies, "; "))
	r := bufio.NewReader(conn)
	resp, err := http.ReadResponse(r, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", resp, err)
	}
	if op, payload := readFrame(t, conn, r); op != 1 || !strings.Contains(string(payload), `"t":"hello"`) {
		t.Fatalf("first frame %d %q", op, payload)
	}
	return conn, r
}

// readFrame reads one unmasked server frame.
func readFrame(t *testing.T, conn net.Conn, r *bufio.Reader) (byte, []byte) {
	t.Helper()
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		t.Fatalf("read frame: %v", err)
	}
	n := uint64(h[1] & 0x7f)
	switch n {
	case 126:
		var b [2]byte
		_, _ = io.ReadFull(r, b[:])
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		_, _ = io.ReadFull(r, b[:])
		n = binary.BigEndian.Uint64(b[:])
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	return h[0] & 0x0f, payload
}

// A password reset by the administrator command in its own process ends
// the realtime connections of the running server within two seconds
// (close 4003), as the Python release did, and not only at the periodic
// re-check.
func TestResetPasswordInAnotherProcessEndsServerSessions(t *testing.T) {
	if testing.Short() {
		t.Skip("starts the server and the command as processes")
	}
	dir := t.TempDir()
	port := freePort(t)
	base := "http://127.0.0.1:" + port
	env := []string{"DATA_DIR=" + filepath.Join(dir, "data"), "SECRET_KEY=cross-process-test-secret-0123456789abcdef",
		"SESSION_COOKIE_SECURE=false", "BOOTSTRAP_REGISTRATION_ENABLED=true", "TMPDIR=" + dir}
	server := webssh(t, env, "serve", "--bind", "127.0.0.1:"+port)
	logs, _ := os.Create(filepath.Join(dir, "server.log"))
	server.Stdout, server.Stderr = logs, logs
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = server.Process.Signal(os.Interrupt)
		_ = server.Wait()
		if t.Failed() {
			out, _ := os.ReadFile(filepath.Join(dir, "server.log"))
			t.Logf("server log:\n%s", out)
		}
	})
	deadline := time.Now().Add(20 * time.Second)
	for {
		resp, err := http.Get(base + "/ready")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("server not ready")
		}
		time.Sleep(100 * time.Millisecond)
	}

	client := signUp(t, base, "admin1", "first-password-1")
	conn, r := openRealtime(t, client, base)

	pwFile := filepath.Join(dir, "new-password")
	if err := os.WriteFile(pwFile, []byte("second-password-2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cli := webssh(t, env, "reset-password", "--username", "admin1", "--password-file", pwFile)
	out, err := cli.CombinedOutput()
	if err != nil {
		t.Fatalf("reset-password: %v\n%s", err, out)
	}
	reset := time.Now()
	_ = conn.SetReadDeadline(reset.Add(2 * time.Second))
	for {
		op, payload := readFrame(t, conn, r)
		if op != 8 {
			continue // events sent before the revocation
		}
		if code := binary.BigEndian.Uint16(payload); code != 4003 {
			t.Fatalf("close code %d %q", code, payload[2:])
		}
		break
	}
	if took := time.Since(reset); took > 2*time.Second {
		t.Fatalf("revocation took %v", took)
	}
	resp, err := client.Get(base + "/api/realtime/status")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session still valid: %d", resp.StatusCode)
	}
	if errors.Is(context.Cause(t.Context()), context.Canceled) {
		t.Fatal("test context ended")
	}
}
