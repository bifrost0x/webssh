package protocol

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/ntlm"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/require"
)

// recordingTransport hands every packet the fake server reads to reads, so
// a test can see the request that ended the fake session-setup exchange.
type recordingTransport struct {
	Transport
	reads chan []byte
}

func (r *recordingTransport) readPacket(findSink ...directSinkFinder) (*recvPacket, error) {
	rp, err := r.Transport.readPacket(findSink...)
	if err == nil {
		select {
		case r.reads <- append([]byte(nil), rp.bytes()...):
		default:
		}
	}
	return rp, err
}

// setupRequireEncryption runs a complete NTLM session setup against the fake
// server on a SMB 3.0.2 connection with the given cipher.
func setupRequireEncryption(t *testing.T, cipherId uint16, requireEncryption bool) (*session, *recordingTransport, <-chan struct{}, error) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
	})
	st := &recordingTransport{Transport: NewTransport(serverConn), reads: make(chan []byte, 8)}
	ntlmServer := ntlm.NewServer("test-server")
	ntlmServer.AddAccount("user", "password")
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		runFakeSessionSetupServer(st, sessionSetupServerSuccess, ntlmServer)
	}()

	c, cleanup := newBenchConn(clientConn)
	t.Cleanup(cleanup)
	c.cipherId = cipherId
	c.requireEncryption = requireEncryption
	s, err := c.sessionSetup(context.Background(), &testNTLMInitiator{User: "user", Password: "password"})
	return s, st, serverDone, err
}

func TestSessionSetupRequireEncryption(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name              string
		cipherId          uint16
		requireEncryption bool
		wantErr           error
		wantEncrypt       bool
	}{
		{name: "cipher negotiated", cipherId: wire.AES128CCM, requireEncryption: true, wantEncrypt: true},
		{name: "no cipher negotiated", cipherId: 0, requireEncryption: true, wantErr: ErrEncryptionUnavailable},
		{name: "not required, cipher negotiated", cipherId: wire.AES128CCM},
		{name: "not required, no cipher", cipherId: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, _, _, err := setupRequireEncryption(t, tt.cipherId, tt.requireEncryption)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				require.Nil(t, s)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, s)
			info := (&Session{s: s}).SecurityInfo()
			require.Equal(t, tt.wantEncrypt, info.EncryptData)
			require.Equal(t, tt.wantEncrypt, s.sessionFlags&wire.SMB2_SESSION_FLAG_ENCRYPT_DATA != 0)
			require.Equal(t, Cipher(tt.cipherId), info.Cipher)
			require.Equal(t, Dialect(wire.SMB302), info.Dialect)
			require.False(t, info.Guest)
			require.False(t, info.Null)
		})
	}
}

// TestRequireEncryptionRejectsPlaintextResponse checks both directions after
// session setup: requests leave as transform packets, and a plaintext
// response to them is refused.
func TestRequireEncryptionRejectsPlaintextResponse(t *testing.T) {
	t.Parallel()
	s, st, serverDone, err := setupRequireEncryption(t, wire.AES128CCM, true)
	require.NoError(t, err)

	echoErr := make(chan error, 1)
	go func() { echoErr <- s.echo(context.Background()) }()

	// The fake server stops at the first request after session setup.
	select {
	case <-serverDone:
	case <-time.After(10 * time.Second):
		t.Fatal("fake server did not read the request after session setup")
	}
	var req []byte
	for len(st.reads) > 0 {
		req = <-st.reads
	}
	require.GreaterOrEqual(t, len(req), 4)
	require.Equal(t, []byte(wire.MAGIC2), req[:4], "request after session setup is not encrypted")

	// The client's encryption key is the server's decryption key.
	plain, err := (&session{decrypter: s.encrypter}).decrypt(req)
	require.NoError(t, err)
	require.Equal(t, wire.SMB2_ECHO, wire.PacketCodec(plain).Command())

	sendTestResponse(st, plain, &wire.EchoResponse{}, uint32(erref.STATUS_SUCCESS))
	select {
	case err := <-echoErr:
		var ierr *InvalidResponseError
		require.ErrorAs(t, err, &ierr)
		require.ErrorContains(t, err, "encrypted response required")
	case <-time.After(10 * time.Second):
		t.Fatal("plaintext response was not rejected")
	}
}

func TestDialRequireEncryptionRejectsAnonymousInitiator(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	received := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		if _, err := serverConn.Read(buf); err == nil {
			close(received)
		}
	}()

	_, err := (&Dialer{RequireEncryption: true}).Dial(context.Background(), &singleRoundInitiator{anonymous: true}, NewTransport(clientConn))
	require.ErrorIs(t, err, ErrCredentialsRequired)

	buf := make([]byte, 1)
	_, readErr := clientConn.Read(buf)
	require.Error(t, readErr, "Dial left the transport open")
	select {
	case <-received:
		t.Fatal("Dial sent data for an anonymous initiator")
	default:
	}
}

func TestSecurityInfoZeroValues(t *testing.T) {
	t.Parallel()
	var nilSession *Session
	require.Equal(t, SecurityInfo{}, nilSession.SecurityInfo())
	require.Equal(t, SecurityInfo{}, (&Session{}).SecurityInfo())

	var nilTree *Tree
	require.Zero(t, nilTree.ShareFlags())
	require.False(t, nilTree.IsDFS())
	require.False(t, nilTree.Encrypted())
}

func TestTreeSecurityFlags(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		sessionFlags  uint16
		shareFlags    uint32
		isDFSShare    bool
		wantDFS       bool
		wantEncrypted bool
	}{
		{name: "plain"},
		{name: "session encrypts", sessionFlags: wire.SMB2_SESSION_FLAG_ENCRYPT_DATA, wantEncrypted: true},
		{name: "share encrypts", shareFlags: wire.SMB2_SHAREFLAG_ENCRYPT_DATA, wantEncrypted: true},
		{name: "DFS share flag", shareFlags: wire.SMB2_SHAREFLAG_DFS, wantDFS: true},
		{name: "DFS root flag", shareFlags: wire.SMB2_SHAREFLAG_DFS_ROOT, wantDFS: true},
		{name: "DFS capability", isDFSShare: true, wantDFS: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tc := &Tree{session: &session{sessionFlags: tt.sessionFlags}, shareFlags: tt.shareFlags, isDFSShare: tt.isDFSShare}
			require.Equal(t, tt.shareFlags, tc.ShareFlags())
			require.Equal(t, tt.wantDFS, tc.IsDFS())
			require.Equal(t, tt.wantEncrypted, tc.Encrypted())
		})
	}
}
