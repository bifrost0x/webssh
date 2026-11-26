package smb2

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/auth"
	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/utf16le"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/require"
)

// refusingTransportDialer fails the test when Dial opens a transport.
type refusingTransportDialer struct{ t *testing.T }

func (d refusingTransportDialer) Dial(context.Context, string) (Transport, error) {
	d.t.Error("Dial opened a transport")
	return nil, errors.New("unexpected transport dial")
}

func TestDialRequireEncryptionRefusesEmptyCredentials(t *testing.T) {
	t.Parallel()
	d := &Dialer{
		Credentials:       auth.NTLMCredential{},
		TransportDialer:   refusingTransportDialer{t: t},
		RequireEncryption: true,
	}
	session, err := d.Dial(context.Background(), "server.example")
	require.ErrorIs(t, err, ErrCredentialsRequired)
	require.Nil(t, session)
}

// TestDialRequireEncryptionFailsWithoutCipher dials a server that offers no
// encryption (SMB 2.1, guest). Without RequireEncryption the same exchange
// succeeds (TestDialReturnsIndependentSessions); with it Dial must fail.
func TestDialRequireEncryptionFailsWithoutCipher(t *testing.T) {
	t.Parallel()
	for _, required := range []bool{false, true} {
		dialer := &Dialer{
			Credentials: testCredentialsFunc(func(context.Context, string) (auth.Initiator, error) {
				return &singleRoundInitiator{key: []byte("0123456789abcdef")}, nil
			}),
			SpecifiedDialects: []Dialect{SMB210},
			TransportDialer: transportDialerFunc(func(context.Context, string) (Transport, error) {
				client, server := net.Pipe()
				t.Cleanup(func() { _ = server.Close() })
				go serveDialTestSession(server, nil)
				return NewTransport(client), nil
			}),
			RequireEncryption: required,
		}
		session, err := dialer.Dial(context.Background(), "server")
		if !required {
			require.NoError(t, err)
			require.False(t, session.SecurityInfo().EncryptData)
			_ = session.Close()
			continue
		}
		require.ErrorIs(t, err, ErrEncryptionUnavailable)
		require.Nil(t, session)
	}
}

// TestShareInfo covers the TREE_CONNECT properties of unencrypted trees; the
// encryption flags are covered by TestTreeSecurityFlags in x/protocol, since
// the fake server here cannot encrypt.
func TestShareInfo(t *testing.T) {
	t.Parallel()
	var nilShare *Share
	require.Equal(t, ShareInfo{}, nilShare.Info())

	tests := []struct {
		name    string
		options testServerOptions
		want    ShareInfo
	}{
		{
			name:    "plain disk share",
			options: testServerOptions{shareType: wire.SMB2_SHARE_TYPE_DISK},
			want:    ShareInfo{ShareType: wire.SMB2_SHARE_TYPE_DISK},
		},
		{
			name:    "DFS share",
			options: testServerOptions{shareType: wire.SMB2_SHARE_TYPE_DISK, shareFlags: wire.SMB2_SHAREFLAG_DFS, isDFSShare: true},
			want:    ShareInfo{ShareType: wire.SMB2_SHARE_TYPE_DISK, ShareFlags: wire.SMB2_SHAREFLAG_DFS, DFS: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fs, _ := newProtocolTestShare(t, tt.options)
			require.Equal(t, tt.want, fs.Info())
		})
	}
}

// createRequestName decodes the name of the CREATE request in reqBuf.
func createRequestName(reqBuf []byte) string {
	req := wire.CreateRequestDecoder(reqBuf[64:])
	off, size := int(req.NameOffset()), int(req.NameLength())
	return utf16le.DecodeToString(reqBuf[off : off+size])
}

func TestShareOpenWithSendsExactCreate(t *testing.T) {
	t.Parallel()
	fs, serverConn := newProtocolTestShare(t)
	spec := OpenSpec{
		DesiredAccess:     wire.FILE_READ_ATTRIBUTES | wire.FILE_ADD_FILE | wire.FILE_ADD_SUBDIRECTORY | wire.FILE_DELETE_CHILD,
		ShareAccess:       wire.FILE_SHARE_READ,
		CreateDisposition: wire.FILE_OPEN,
		CreateOptions:     wire.FILE_DIRECTORY_FILE | wire.FILE_OPEN_REPARSE_POINT,
		FileAttributes:    wire.FILE_ATTRIBUTE_DIRECTORY,
	}

	type seen struct {
		name                                string
		access, share, disposition, options uint32
		attributes                          uint32
		oplock                              uint8
	}
	observed := make(chan seen, 1)
	go func() {
		reqBuf, err := readMsg(serverConn)
		if err != nil || wire.PacketCodec(reqBuf).Command() != wire.SMB2_CREATE {
			close(observed)
			return
		}
		req := wire.CreateRequestDecoder(reqBuf[64:])
		observed <- seen{
			name: createRequestName(reqBuf), access: req.DesiredAccess(), share: req.ShareAccess(),
			disposition: req.CreateDisposition(), options: req.CreateOptions(), attributes: req.FileAttributes(),
			oplock: req.RequestedOplockLevel(),
		}
		sendTestResponse(serverConn, reqBuf, &wire.CreateResponse{FileId: wire.FileId{Persistent: [8]byte{7}}, FileAttributes: wire.FILE_ATTRIBUTE_DIRECTORY}, 0)
		if reqBuf, err := readMsg(serverConn); err == nil && wire.PacketCodec(reqBuf).Command() == wire.SMB2_CLOSE {
			sendTestCloseResponse(serverConn, reqBuf)
		}
	}()

	f, err := fs.OpenWith(context.Background(), "dir/sub", spec)
	require.NoError(t, err)
	require.False(t, f.readAccess, "a directory opened without read access must not allow reads")
	require.NoError(t, f.Close(context.Background()))

	got, ok := <-observed
	require.True(t, ok, "server did not receive a CREATE")
	require.Equal(t, seen{
		name: `dir\sub`, access: spec.DesiredAccess, share: spec.ShareAccess,
		disposition: spec.CreateDisposition, options: spec.CreateOptions, attributes: spec.FileAttributes,
		oplock: wire.SMB2_OPLOCK_LEVEL_NONE,
	}, got)
}

func TestShareOpenWithReadAccess(t *testing.T) {
	t.Parallel()
	for _, access := range []uint32{wire.FILE_READ_DATA, wire.GENERIC_READ, wire.GENERIC_ALL} {
		fs, serverConn := newProtocolTestShare(t)
		go func() {
			reqBuf, err := readMsg(serverConn)
			if err != nil {
				return
			}
			sendTestResponse(serverConn, reqBuf, &wire.CreateResponse{FileId: wire.FileId{Persistent: [8]byte{8}}}, 0)
			if reqBuf, err := readMsg(serverConn); err == nil {
				sendTestCloseResponse(serverConn, reqBuf)
			}
		}()
		f, err := fs.OpenWith(context.Background(), "file.txt", OpenSpec{DesiredAccess: access, CreateDisposition: wire.FILE_OPEN})
		require.NoError(t, err)
		require.True(t, f.readAccess, "access %#x", access)
		require.NoError(t, f.Close(context.Background()))
	}
}

// TestShareOpenWithDoesNotFollowSymlinks answers the CREATE with a valid
// symbolic-link error. OpenFile would retry against the link target; OpenWith
// must fail and send nothing more.
func TestShareOpenWithDoesNotFollowSymlinks(t *testing.T) {
	t.Parallel()
	fs, serverConn := newProtocolTestShare(t)
	names := make(chan string, 1)
	go func() {
		reqBuf, err := readMsg(serverConn)
		if err != nil {
			close(names)
			return
		}
		names <- createRequestName(reqBuf)
		sendTestResponse(serverConn, reqBuf, &wire.ErrorResponse{
			CommandCode: wire.SMB2_CREATE,
			ErrorData: &wire.SymbolicLinkErrorResponse{
				Flags:          wire.SYMLINK_FLAG_RELATIVE,
				SubstituteName: `target.txt`,
				PrintName:      `target.txt`,
			},
		}, uint32(erref.STATUS_STOPPED_ON_SYMLINK))
	}()

	f, err := fs.OpenWith(context.Background(), `dir\link\file.txt`, OpenSpec{DesiredAccess: wire.FILE_READ_ATTRIBUTES, CreateDisposition: wire.FILE_OPEN})
	require.Error(t, err)
	require.Nil(t, f)
	require.Equal(t, `dir\link\file.txt`, <-names)
	requireNoRequest(t, serverConn)
}

func TestShareOpenWithRejectsInvalidInput(t *testing.T) {
	t.Parallel()
	var nilShare *Share
	_, err := nilShare.OpenWith(context.Background(), "a", OpenSpec{})
	require.Error(t, err)

	fs, serverConn := newProtocolTestShare(t)
	for _, name := range []string{"../escape", `a\..\..\b`, "a/./b"} {
		_, err := fs.OpenWith(context.Background(), name, OpenSpec{DesiredAccess: wire.FILE_READ_ATTRIBUTES, CreateDisposition: wire.FILE_OPEN})
		require.Error(t, err, name)
	}
	requireNoRequest(t, serverConn)
}
