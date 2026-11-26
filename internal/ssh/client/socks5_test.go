package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
)

type scripted struct {
	in  *bytes.Reader
	out bytes.Buffer
}

func (s *scripted) Read(p []byte) (int, error)  { return s.in.Read(p) }
func (s *scripted) Write(p []byte) (int, error) { return s.out.Write(p) }

func TestSOCKSHandshake(t *testing.T) {
	okReply := []byte{5, 0, 0, 1, 10, 0, 0, 1, 0, 22}
	cases := []struct {
		name   string
		host   string
		server []byte
		sent   []byte
		code   string
	}{
		{"ipv4", "10.1.2.3", append([]byte{5, 0}, okReply...), []byte{5, 1, 0, 5, 1, 0, 1, 10, 1, 2, 3, 0, 22}, ""},
		{"name", "h.test", append([]byte{5, 0}, okReply...), append([]byte{5, 1, 0, 5, 1, 0, 3, 6}, append([]byte("h.test"), 0, 22)...), ""},
		{"ipv6", "::1", append([]byte{5, 0}, okReply...), append([]byte{5, 1, 0, 5, 1, 0, 4}, append(make([]byte, 15), 1, 0, 22)...), ""},
		{"domain in reply", "h", []byte{5, 0, 5, 0, 0, 3, 3, 'a', 'b', 'c', 0, 22}, nil, ""},
		{"auth required", "h", []byte{5, 0xff}, nil, "socks_auth_required"},
		{"other method", "h", []byte{5, 2}, nil, "socks_protocol_error"},
		{"refused", "h", []byte{5, 0, 5, 5, 0, 1}, nil, "socks_connection_refused"},
		{"not allowed", "h", []byte{5, 0, 5, 2, 0, 1}, nil, "socks_not_allowed"},
		{"unknown reply", "h", []byte{5, 0, 5, 9, 0, 1}, nil, "socks_protocol_error"},
		{"bad address type", "h", []byte{5, 0, 5, 0, 0, 9}, nil, "socks_protocol_error"},
		{"truncated", "h", []byte{5}, nil, "socks_protocol_error"},
		{"not socks5", "h", []byte{4, 0}, nil, "socks_protocol_error"},
		{"zone", "fe80::1%eth0", nil, nil, "socks_protocol_error"},
		{"long name", string(make([]byte, 256)), nil, nil, "socks_protocol_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &scripted{in: bytes.NewReader(tc.server)}
			err := socksHandshake(s, tc.host, 22)
			se, _ := errors.AsType[*SOCKSError](err)
			switch {
			case tc.code == "" && err != nil:
				t.Fatal(err)
			case tc.code != "" && (se == nil || se.Code != tc.code):
				t.Fatalf("want %s, got %v", tc.code, err)
			case tc.sent != nil && !bytes.Equal(s.out.Bytes(), tc.sent):
				t.Fatalf("sent %v, want %v", s.out.Bytes(), tc.sent)
			}
			if se != nil && socksMessages[se.Code] == "" {
				t.Fatalf("%s has no message", se.Code)
			}
		})
	}
}

// A SOCKS5 failure keeps its Python code as detail, its Python text as
// message, and names the proxy as the failing hop.
func TestSOCKSErrorsThroughTheDialer(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 3)
				_, _ = io.ReadFull(c, buf)
				_, _ = c.Write([]byte{5, 0})
				buf = make([]byte, 64)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
			}()
		}
	}()
	d, _ := newDialer(trusting(), nil)
	addr := l.Addr().(*net.TCPAddr)
	tgt := Target{Owner: 1, Hop: Hop{Host: "h.test", Port: 22, User: "u", Auth: Auth{Password: "x"}}, Proxy: &SOCKS{Host: "127.0.0.1", Port: addr.Port}}
	_, err = d.Dial(t.Context(), tgt, nil)
	he, _ := errors.AsType[*HopError](err)
	status, code, message := fault.Status(err)
	if he == nil || he.Role != RoleSOCKS || he.Detail != "socks_host_unreachable" || code != fault.Unreachable || status != 502 || message != socksMessages["socks_host_unreachable"] {
		t.Fatalf("got %v (%d %s %q)", err, status, code, message)
	}
	tgt.Proxy.Port = 1
	_, err = d.Dial(t.Context(), tgt, nil)
	if he, _ := errors.AsType[*HopError](err); he == nil || he.Detail != "socks_proxy_unreachable" {
		t.Fatalf("proxy down: %v", err)
	}
}

func TestSOCKSHonoursContext(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := socksConnect(ctx, client, "h.test", 22); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("handshake did not stop")
	}
}

func FuzzSOCKSReply(f *testing.F) {
	f.Add([]byte{5, 0, 5, 0, 0, 1, 1, 2, 3, 4, 0, 22})
	f.Add([]byte{5, 0, 5, 0, 0, 3, 255})
	f.Add([]byte{5, 0, 5, 0, 0, 3, 0, 0, 22})
	f.Fuzz(func(t *testing.T, server []byte) {
		s := &scripted{in: bytes.NewReader(server)}
		err := socksHandshake(s, "h.test", 22)
		// Shortest valid exchange: method 2, reply head 4, empty name 1,
		// port 2.
		if err == nil && len(server) < 9 {
			t.Fatalf("accepted short reply %v", server)
		}
		if _, ok := errors.AsType[*SOCKSError](err); err != nil && !ok {
			t.Fatalf("unclassified error %v", err)
		}
	})
}
