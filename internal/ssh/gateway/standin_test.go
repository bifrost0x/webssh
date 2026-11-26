package gateway

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// standIn is an in-process SSH server that behaves like Warpgate as
// far as WebSSH can see: selectors as usernames, publickey then a one-time
// code, and an in-band host-key question on the session PTY before the
// target runs the command. It records the methods clients used.
type standIn struct {
	t        *testing.T
	port     int
	hostKey  ssh.PublicKey
	clientPK ssh.PublicKey

	// Behaviour knobs.
	methods     string // "key+otp", "otp", "password", "ki-broken+password", "password+otp"
	otp         string
	password    string
	askHostKey  bool // print a host-key question and wait for "y"
	noMarker    bool // print something else instead of the marker
	exitStatus  uint32
	floodOutput int // bytes to print before the marker

	mu       sync.Mutex
	attempts []string
}

func (g *standIn) record(m string) {
	g.mu.Lock()
	g.attempts = append(g.attempts, m)
	g.mu.Unlock()
}

func (g *standIn) used() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.attempts...)
}

func newStandIn(t *testing.T, methods string) (*standIn, ssh.Signer) {
	t.Helper()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	_, clientPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientSigner, _ := ssh.NewSignerFromKey(clientPriv)
	g := &standIn{t: t, hostKey: hostSigner.PublicKey(), clientPK: clientSigner.PublicKey(),
		methods: methods, otp: "424242", password: "synthetic-" + rand.Text()}

	cfg := &ssh.ServerConfig{MaxAuthTries: 10}
	otp := func(c ssh.ConnMetadata, ch ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		g.record("keyboard-interactive")
		answers, err := ch("Warpgate", "Enter the one-time code for "+c.User(), []string{"OTP: "}, []bool{false})
		if err != nil || len(answers) != 1 || answers[0] != g.otp {
			return nil, errors.New("bad otp")
		}
		return nil, nil
	}
	password := func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		g.record("password")
		if string(pw) != g.password {
			return nil, errors.New("bad password")
		}
		return nil, nil
	}
	switch methods {
	case "key+otp":
		cfg.PublicKeyCallback = func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			g.record("publickey")
			if !bytes.Equal(k.Marshal(), g.clientPK.Marshal()) {
				return nil, errors.New("unknown key")
			}
			return nil, &ssh.PartialSuccessError{Next: ssh.ServerAuthCallbacks{KeyboardInteractiveCallback: otp}}
		}
	case "password+otp":
		cfg.PasswordCallback = func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if _, err := password(c, pw); err != nil {
				return nil, err
			}
			return nil, &ssh.PartialSuccessError{Next: ssh.ServerAuthCallbacks{KeyboardInteractiveCallback: otp}}
		}
	case "otp":
		cfg.KeyboardInteractiveCallback = otp
	case "password":
		cfg.PasswordCallback = password
	case "ki-broken+password":
		// Advertises keyboard-interactive without a working backend.
		cfg.KeyboardInteractiveCallback = func(ssh.ConnMetadata, ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			g.record("keyboard-interactive")
			return nil, errors.New("no backend")
		}
		cfg.PasswordCallback = password
	case "ki+password":
		cfg.KeyboardInteractiveCallback = otp
		cfg.PasswordCallback = password
	default:
		t.Fatalf("unknown methods %q", methods)
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g.port = ln.Addr().(*net.TCPAddr).Port
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	wg.Go(func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() { g.serve(conn, cfg) })
		}
	})
	return g, clientSigner
}

var markerCommand = regexp.MustCompile(`^printf '\\n%s\\n' (WEBSSH_READY_[0-9a-f]{32})$`)

func (g *standIn) serve(conn net.Conn, cfg *ssh.ServerConfig) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer func() { _ = sc.Close() }()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			return
		}
		go g.session(ch, chReqs)
	}
}

func (g *standIn) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer func() { _ = ch.Close() }()
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			_ = req.Reply(true, nil)
		case "subsystem":
			_ = req.Reply(true, nil)
			if g.askHostKey {
				_, _ = fmt.Fprint(ch.Stderr(), "")
			}
			_, _ = ch.Write([]byte{0, 0, 0, 5, 2, 0, 0, 0, 3}) // SSH_FXP_VERSION 3
			continue
		case "exec":
			var payload struct{ Command string }
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				_ = req.Reply(false, nil)
				return
			}
			m := markerCommand.FindStringSubmatch(payload.Command)
			_ = req.Reply(m != nil, nil)
			if m == nil {
				return
			}
			g.run(ch, m[1])
			return
		default:
			_ = req.Reply(false, nil)
		}
	}
}

func (g *standIn) run(ch ssh.Channel, marker string) {
	if g.askHostKey {
		_, _ = ch.Write([]byte("Host key for target prod is unknown: SHA256:synthetic\r\nTrust it? [y/N] "))
		buf := make([]byte, 16)
		n, _ := ch.Read(buf)
		if n == 0 || buf[0] != 'y' {
			_, _ = ch.Write([]byte("\r\nrejected\r\n"))
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ S uint32 }{1}))
			return
		}
		_, _ = ch.Write([]byte("y\r\n"))
	}
	if g.floodOutput > 0 {
		chunk := append(bytes.Repeat([]byte("ä"), 1023), '\r', '\n') // two-byte runes across frame edges
		for sent := 0; sent < g.floodOutput; sent += len(chunk) {
			if _, err := ch.Write(chunk); err != nil {
				return
			}
		}
	}
	if g.noMarker {
		marker = "WEBSSH_READY_0000"
	}
	_, _ = ch.Write([]byte("\r\n" + marker + "\r\n"))
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ S uint32 }{g.exitStatus}))
}
