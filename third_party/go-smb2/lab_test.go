package smb2

// Tests of the local patch against the WebSSH test lab (Samba and Windows
// Server). They are not part of the patch intended for upstream. Set
// WEBSSH_SMB_LAB to the lab.json of a running lab (tests/lab in the WebSSH
// repository); without it they skip.

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/auth"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/require"
)

type labTarget struct {
	name, share, user, password string
	domain                      *string
	port                        int
	encryptedShare              bool
}

func readLabSecret(t *testing.T, dir, rel string) string {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, filepath.FromSlash(rel)))
	require.NoError(t, err)
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Scan()
	require.NoError(t, s.Err())
	return strings.TrimRight(s.Text(), "\r\n")
}

func labTargets(t *testing.T) []labTarget {
	t.Helper()
	path := os.Getenv("WEBSSH_SMB_LAB")
	if path == "" {
		t.Skip("set WEBSSH_SMB_LAB to the lab.json of a running test lab")
	}
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var lab struct {
		Services struct {
			Samba struct {
				Port  int `json:"port"`
				Users []struct {
					Username, Domain string
					PasswordFile     string `json:"password_file"`
				} `json:"users"`
			} `json:"samba"`
			Windows struct {
				SMBPort int    `json:"smb_port"`
				Share   string `json:"share"`
				Users   []struct {
					Username     string
					PasswordFile string `json:"password_file"`
				} `json:"users"`
			} `json:"windows"`
		} `json:"services"`
	}
	require.NoError(t, json.Unmarshal(raw, &lab))
	dir := filepath.Dir(path)
	var targets []labTarget
	for _, u := range lab.Services.Samba.Users {
		if u.Username != "smbuser" {
			continue
		}
		domain := u.Domain
		password := readLabSecret(t, dir, u.PasswordFile)
		targets = append(targets,
			labTarget{name: "samba-secure", share: "Secure", user: u.Username, password: password, domain: &domain, port: lab.Services.Samba.Port, encryptedShare: true},
			labTarget{name: "samba-plain", share: "Plain", user: u.Username, password: password, domain: &domain, port: lab.Services.Samba.Port},
		)
	}
	if os.Getenv("WEBSSH_SMB_LAB_NO_WINDOWS") == "" && lab.Services.Windows.SMBPort != 0 {
		for _, u := range lab.Services.Windows.Users {
			if u.Username == "smbuser" {
				targets = append(targets, labTarget{name: "windows", share: lab.Services.Windows.Share, user: u.Username,
					password: readLabSecret(t, dir, u.PasswordFile), port: lab.Services.Windows.SMBPort})
			}
		}
	}
	require.NotEmpty(t, targets)
	return targets
}

// frameCounter parses the Direct TCP stream in one direction and counts the
// protocol IDs of the SMB messages it carries.
type frameCounter struct {
	mu     sync.Mutex
	buf    []byte
	counts map[string]int
	order  []string
}

func (c *frameCounter) add(p []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buf = append(c.buf, p...)
	for len(c.buf) >= 8 {
		size := int(binary.BigEndian.Uint32(c.buf[:4]) & 0xffffff)
		if len(c.buf) < 4+size {
			return
		}
		id := fmt.Sprintf("%x", c.buf[4])
		if c.counts == nil {
			c.counts = map[string]int{}
		}
		c.counts[id]++
		c.order = append(c.order, id)
		c.buf = c.buf[4+size:]
	}
}

func (c *frameCounter) snapshot() (map[string]int, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	counts := map[string]int{}
	for k, v := range c.counts {
		counts[k] = v
	}
	return counts, append([]string(nil), c.order...)
}

type sniffedConn struct {
	net.Conn
	sent, received *frameCounter
}

func (c *sniffedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.sent.add(p[:n])
	return n, err
}

func (c *sniffedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.received.add(p[:n])
	return n, err
}

type sniffer struct {
	dials          int
	sent, received frameCounter
}

func (s *sniffer) dialer(port int) TransportDialer {
	return transportDialerFunc(func(ctx context.Context, _ string) (Transport, error) {
		s.dials++
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			return nil, err
		}
		return NewTransport(&sniffedConn{Conn: conn, sent: &s.sent, received: &s.received}), nil
	})
}

func labDialer(tg labTarget, s *sniffer, requireEncryption bool) *Dialer {
	return &Dialer{
		Credentials:           auth.NTLMCredential{User: tg.user, Password: tg.password, Domain: tg.domain},
		TransportDialer:       s.dialer(tg.port),
		RequireMessageSigning: true,
		SpecifiedDialects:     []Dialect{SMB311},
		RequireEncryption:     requireEncryption,
		DisableAAPLExtension:  true,
	}
}

const (
	frameSMB2        = "fe"
	frameTransform   = "fd"
	frameCompression = "fc"
)

// requireEncryptedAfterSetup checks that a direction carries exactly the
// unencrypted NEGOTIATE and SESSION_SETUP exchange first (three messages for
// NTLM) and nothing but transform packets afterwards.
func requireEncryptedAfterSetup(t *testing.T, direction string, order []string) {
	t.Helper()
	require.GreaterOrEqual(t, len(order), 4, "%s: too few messages", direction)
	for i, id := range order {
		if i < 3 {
			require.Equal(t, frameSMB2, id, "%s: handshake message %d", direction, i)
			continue
		}
		require.Equal(t, frameTransform, id, "%s: message %d after session setup is not encrypted (%v)", direction, i, order)
	}
}

func TestLabRequireEncryption(t *testing.T) {
	for _, tg := range labTargets(t) {
		t.Run(tg.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()
			var s sniffer
			session, err := labDialer(tg, &s, true).Dial(ctx, "127.0.0.1")
			require.NoError(t, err)
			defer session.Close()

			info := session.SecurityInfo()
			require.Equal(t, Dialect(SMB311), info.Dialect)
			require.NotZero(t, info.Cipher)
			require.True(t, info.EncryptData)
			require.True(t, info.SigningRequired)
			require.False(t, info.Guest)
			require.False(t, info.Null)
			t.Logf("cipher %#x, signing algorithm %#x", info.Cipher, info.SigningAlgorithm)

			fs, err := session.Mount(ctx, tg.share)
			require.NoError(t, err)
			defer fs.Unmount(context.Background())
			share := fs.Info()
			require.Equal(t, uint8(wire.SMB2_SHARE_TYPE_DISK), share.ShareType)
			require.True(t, share.Encrypted)
			require.False(t, share.DFS)
			require.Equal(t, tg.encryptedShare, share.ShareFlags&wire.SMB2_SHAREFLAG_ENCRYPT_DATA != 0, "share flags %#x", share.ShareFlags)

			name := fmt.Sprintf("sm0-lab-%d.txt", time.Now().UnixNano())
			payload := []byte("encrypted on every share\n")
			require.NoError(t, fs.WriteFile(ctx, name, payload, 0o600))
			defer fs.Remove(context.Background(), name)
			got, err := fs.ReadFile(ctx, name)
			require.NoError(t, err)
			require.Equal(t, payload, got)

			f, err := fs.OpenWith(ctx, name, OpenSpec{
				DesiredAccess:     wire.FILE_READ_DATA | wire.FILE_READ_ATTRIBUTES,
				ShareAccess:       wire.FILE_SHARE_READ,
				CreateDisposition: wire.FILE_OPEN,
				CreateOptions:     wire.FILE_NON_DIRECTORY_FILE | wire.FILE_OPEN_REPARSE_POINT,
			})
			require.NoError(t, err)
			buf := make([]byte, len(payload))
			_, err = f.ReadAt(ctx, buf, 0)
			require.NoError(t, err)
			require.Equal(t, payload, buf)
			require.NoError(t, f.Close(ctx))

			require.NoError(t, fs.Remove(ctx, name))
			sent, sentOrder := s.sent.snapshot()
			received, receivedOrder := s.received.snapshot()
			t.Logf("sent %v, received %v", sent, received)
			requireEncryptedAfterSetup(t, "client to server", sentOrder)
			requireEncryptedAfterSetup(t, "server to client", receivedOrder)
			require.Zero(t, sent[frameCompression]+received[frameCompression], "compressed messages")
		})
	}
}

// TestLabWithoutRequireEncryption is the control for samba-plain: without
// the option the library would not encrypt a share that does not ask for it.
func TestLabWithoutRequireEncryption(t *testing.T) {
	for _, tg := range labTargets(t) {
		if tg.name != "samba-plain" {
			continue
		}
		ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
		defer cancel()
		var s sniffer
		session, err := labDialer(tg, &s, false).Dial(ctx, "127.0.0.1")
		require.NoError(t, err)
		defer session.Close()
		require.False(t, session.SecurityInfo().EncryptData)
		fs, err := session.Mount(ctx, tg.share)
		require.NoError(t, err)
		require.False(t, fs.Info().Encrypted)
		_, err = fs.ReadDir(ctx, "")
		require.NoError(t, err)
		require.NoError(t, fs.Unmount(ctx))
		sent, _ := s.sent.snapshot()
		require.Zero(t, sent[frameTransform], "plain share encrypted without RequireEncryption")
		require.Positive(t, sent[frameSMB2])
	}
}

func TestLabRejectsCredentials(t *testing.T) {
	for _, tg := range labTargets(t) {
		t.Run(tg.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()

			var empty sniffer
			d := labDialer(tg, &empty, true)
			d.Credentials = auth.NTLMCredential{Domain: tg.domain}
			_, err := d.Dial(ctx, "127.0.0.1")
			require.ErrorIs(t, err, ErrCredentialsRequired)
			require.Zero(t, empty.dials, "a transport was opened for empty credentials")

			var wrong sniffer
			d = labDialer(tg, &wrong, true)
			d.Credentials = auth.NTLMCredential{User: tg.user, Password: tg.password + "-wrong", Domain: tg.domain}
			_, err = d.Dial(ctx, "127.0.0.1")
			require.Error(t, err)
		})
	}
}
