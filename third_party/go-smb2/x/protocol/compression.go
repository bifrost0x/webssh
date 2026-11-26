package protocol

import "errors"

// This fork does not implement SMB2 compression ([MS-SMB2] 3.1.4.4). The
// client never offers it in NEGOTIATE, so a conforming server never selects
// it, compressionEnabled is always false and the send path never compresses.
// A compressed packet from the server, encrypted or not, is rejected before
// any of its content is decoded.

const compressionHeaderSize = 16

var errCompressionUnsupported = errors.New("protocol: compression is not supported")

func maxCompressedPacketSize(size int) int {
	return compressionHeaderSize + size
}

func compressPacketInto(pkt, dst []byte) ([]byte, error) {
	return nil, errCompressionUnsupported
}

func (conn *conn) compressionEnabled() bool {
	return false
}

func decompressPacketForReceive(conn *conn, pkt []byte, findSink directSinkFinder) ([]byte, []byte, error) {
	return nil, nil, &InvalidResponseError{Message: "compression was not negotiated"}
}
