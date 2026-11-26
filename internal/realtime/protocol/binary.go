package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Binary frames carry terminal bytes without JSON, base64 or UTF-8
// re-encoding. Layout (big endian), 14 bytes header followed by data:
//
//	offset 0  kind    uint8
//	offset 1  flags   uint8
//	offset 2  channel uint32  per-connection stream id from terminal.open/attach
//	offset 6  seq     uint64  output: session sequence; input: input sequence;
//	                          ack: highest output sequence processed
//	offset 14 data
//
// The schema version of binary frames is the negotiated subprotocol.
const HeaderLen = 14

// Kind identifies a binary frame.
type Kind uint8

const (
	KindOutput Kind = 1 // server -> client: terminal output
	KindInput  Kind = 2 // client -> server: keystrokes and paste
	KindAck    Kind = 3 // client -> server: cumulative output ack, no data
)

// Output flags.
const (
	// FlagReset: the client clears the terminal before writing this frame.
	// Set on the first frame of a snapshot after attach.
	FlagReset uint8 = 1 << 0
	// FlagReplay: the frame replays buffered output after attach.
	FlagReplay uint8 = 1 << 1
)

// Input flags.
const (
	// FlagWantAck asks the server to confirm this input frame with a
	// terminal.input_ack event (paste progress); keystrokes leave it unset.
	FlagWantAck uint8 = 1 << 0
)

// Frame is a decoded binary frame. Data aliases the input buffer.
type Frame struct {
	Kind    Kind
	Flags   uint8
	Channel uint32
	Seq     uint64
	Data    []byte
}

var (
	errShort = errors.New("protocol: binary frame shorter than header")
	errKind  = errors.New("protocol: unknown binary frame kind")
)

// DecodeFrame parses a binary frame received from a client. Only input and
// ack frames are valid in that direction; maxData bounds input data.
func DecodeFrame(b []byte, maxData int) (Frame, error) {
	if len(b) < HeaderLen {
		return Frame{}, errShort
	}
	f := Frame{
		Kind:    Kind(b[0]),
		Flags:   b[1],
		Channel: binary.BigEndian.Uint32(b[2:6]),
		Seq:     binary.BigEndian.Uint64(b[6:14]),
		Data:    b[HeaderLen:],
	}
	switch f.Kind {
	case KindInput:
		if len(f.Data) == 0 || len(f.Data) > maxData {
			return Frame{}, fmt.Errorf("protocol: input data length %d", len(f.Data))
		}
		if f.Flags&^FlagWantAck != 0 {
			return Frame{}, errors.New("protocol: unknown input flags")
		}
	case KindAck:
		if len(f.Data) != 0 || f.Flags != 0 {
			return Frame{}, errors.New("protocol: ack carries data or flags")
		}
	case KindOutput:
		// Accepted so that a Go client can reuse the decoder.
	default:
		return Frame{}, errKind
	}
	return f, nil
}

// AppendFrame appends the encoded frame to dst.
func AppendFrame(dst []byte, f Frame) []byte {
	var h [HeaderLen]byte
	h[0] = byte(f.Kind)
	h[1] = f.Flags
	binary.BigEndian.PutUint32(h[2:6], f.Channel)
	binary.BigEndian.PutUint64(h[6:14], f.Seq)
	dst = append(dst, h[:]...)
	return append(dst, f.Data...)
}
