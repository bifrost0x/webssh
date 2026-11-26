package protocol

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/require"
)

// compressedPacketForTest wraps pkt in a well-formed unchained compression
// transform header ([MS-SMB2] 2.2.42.1). The payload is not compressed; the
// client must reject the header before it would look at the payload.
func compressedPacketForTest(pkt []byte) []byte {
	out := make([]byte, compressionHeaderSize+len(pkt))
	c := wire.CompressionCodec(out)
	c.SetProtocolId()
	c.SetOriginalCompressedSegmentSize(uint32(len(pkt)))
	c.SetCompressionAlgorithm(wire.SMB2_COMPRESSION_ALGORITHM_LZ4)
	c.SetFlags(wire.SMB2_COMPRESSION_FLAG_NONE)
	c.SetOffset(0)
	copy(out[compressionHeaderSize:], pkt)
	return out
}

func TestCompressionIsNeverEnabled(t *testing.T) {
	t.Parallel()
	require.Empty(t, clientCompressionAlgorithms)
	c := &conn{dialect: wire.SMB311, compressionIds: []uint16{wire.SMB2_COMPRESSION_ALGORITHM_LZ4}}
	require.False(t, c.compressionEnabled())

	_, err := compressPacketInto([]byte("payload"), make([]byte, maxCompressedPacketSize(7)))
	require.ErrorIs(t, err, errCompressionUnsupported)
}

func TestNegotiateRequestOffersNoCompression(t *testing.T) {
	t.Parallel()
	for _, dialects := range [][]Dialect{{SMB311}, clientDialects} {
		req, err := (&Dialer{}).makeNegotiateRequest(dialects, false)
		require.NoError(t, err)
		for _, ctx := range req.Contexts {
			_, compression := ctx.(*wire.CompressionContext)
			require.False(t, compression, "NEGOTIATE offers compression")
		}
	}
}

// TestNegotiateRejectsUnofferedCompression answers NEGOTIATE with a
// compression context the client did not send. Selecting an algorithm is
// refused; an explicit NONE leaves compression off.
func TestNegotiateRejectsUnofferedCompression(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		algorithms []uint16
		invalid    bool
	}{
		{"LZ4", []uint16{wire.SMB2_COMPRESSION_ALGORITHM_LZ4}, true},
		{"LZNT1", []uint16{0x0001}, true},
		{"none", []uint16{wire.SMB2_COMPRESSION_ALGORITHM_NONE}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client, peer := net.Pipe()
			defer peer.Close()
			defer client.Close()
			contexts := wire.NegotiateContexts{&wire.CompressionContext{CompressionAlgorithms: tc.algorithms}}
			done := make(chan error, 1)
			go func() { _, err := signingNegotiatePeer(NewTransport(peer), SMB311, contexts); done <- err }()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := (&Dialer{SpecifiedDialects: []Dialect{SMB311}}).negotiate(ctx, NewTransport(client), openAccount(128))
			if tc.invalid {
				var invalid *InvalidResponseError
				require.ErrorAs(t, err, &invalid)
				require.ErrorContains(t, err, "unsupported compression algorithm")
			} else {
				require.NoError(t, err)
				defer c.close(nil)
				require.Empty(t, c.compressionIds)
				require.False(t, c.compressionEnabled())
			}
			require.NoError(t, <-done)
		})
	}
}

func TestTryDecryptRejectsCompressedPackets(t *testing.T) {
	t.Parallel()
	plain := compressedPacketForTest(make([]byte, 64))

	c := &conn{dialect: wire.SMB311}
	_, _, err := c.tryDecrypt(&recvPacket{pkt: plain})
	require.ErrorContains(t, err, "compression was not negotiated")

	for name, aead := range directIOCiphers(t) {
		t.Run(name, func(t *testing.T) {
			c := &conn{dialect: wire.SMB311}
			c.session = &session{conn: c, sessionId: 7, nonces: &encryptionNonces{}, encrypter: aead, decrypter: aead}
			encrypted, err := c.session.encrypt(plain, make([]byte, 52+len(plain)+aead.Overhead()))
			require.NoError(t, err)
			_, decrypted, err := c.tryDecrypt(&recvPacket{pkt: encrypted})
			require.True(t, decrypted)
			require.ErrorContains(t, err, "compression was not negotiated")
		})
	}
}
