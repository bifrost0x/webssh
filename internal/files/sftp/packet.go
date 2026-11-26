package sftp

import (
	"encoding/binary"
	"errors"
	"unicode/utf8"
)

// SFTP version 3 (draft-ietf-secsh-filexfer-02) packet types.
const (
	fxpInit     = 1
	fxpVersion  = 2
	fxpOpen     = 3
	fxpClose    = 4
	fxpRead     = 5
	fxpWrite    = 6
	fxpLstat    = 7
	fxpFstat    = 8
	fxpSetstat  = 9
	fxpFsetstat = 10
	fxpOpendir  = 11
	fxpReaddir  = 12
	fxpRemove   = 13
	fxpMkdir    = 14
	fxpRmdir    = 15
	fxpRealpath = 16
	fxpStat     = 17
	fxpRename   = 18
	fxpStatus   = 101
	fxpHandle   = 102
	fxpData     = 103
	fxpName     = 104
	fxpAttrs    = 105
	fxpExtended = 200
	fxpExtReply = 201
)

// Status codes of SSH_FXP_STATUS.
const (
	fxOK               = 0
	fxEOF              = 1
	fxNoSuchFile       = 2
	fxPermissionDenied = 3
	fxFailure          = 4
	fxBadMessage       = 5
	fxNoConnection     = 6
	fxConnectionLost   = 7
	fxOpUnsupported    = 8
)

// Attribute flags.
const (
	attrSize        = 0x00000001
	attrUIDGID      = 0x00000002
	attrPermissions = 0x00000004
	attrACModTime   = 0x00000008
	attrExtended    = 0x80000000
	attrKnown       = attrSize | attrUIDGID | attrPermissions | attrACModTime | attrExtended
)

// Bounds of attribute extensions, as in the Python release: at most 16 per
// attribute block and 64 KiB in total.
const (
	maxAttrExtensions        = 16
	maxAttrExtensionBytes    = 64 << 10
	maxVersionExtensions     = 64
	maxVersionExtensionBytes = 256
)

// errMalformed marks a reply that breaks the protocol or the bounds. The
// connection is closed when it is seen.
var errMalformed = errors.New("sftp: malformed or oversized reply")

// attrs is one SFTP v3 attribute block.
type attrs struct {
	flags      uint32
	size       uint64
	uid, gid   uint32
	mode       uint32
	atime      uint32
	mtime      uint32
	extensions int // bytes of extension names and values
}

func (a attrs) has(flag uint32) bool { return a.flags&flag != 0 }

// nameEntry is one member of an SSH_FXP_NAME reply.
type nameEntry struct {
	name     string
	longname int // byte length only; the text is never used
	attrs    attrs
}

// limits bound what the server may send.
type limits struct {
	maxName     int // REMOTE_FILENAME_MAX_BYTES
	maxHandle   int // SFTP_MAX_HANDLE_BYTES
	maxMetadata int // REMOTE_LISTING_MAX_METADATA_BYTES
}

// encoder builds one packet: length, type, request id and payload.
type encoder struct{ b []byte }

func newPacket(typ byte, id uint32) *encoder {
	e := &encoder{b: make([]byte, 4, 64)}
	e.b = append(e.b, typ)
	return e.u32(id)
}

func (e *encoder) u32(v uint32) *encoder { e.b = binary.BigEndian.AppendUint32(e.b, v); return e }

func (e *encoder) str(s string) *encoder {
	e.u32(uint32(len(s))) // #nosec G115 -- request strings are paths and names of at most a few KiB
	e.b = append(e.b, s...)
	return e
}

// mode writes an attribute block with only the permission bits.
func (e *encoder) mode(perm uint32) *encoder { return e.u32(attrPermissions).u32(perm) }

// noAttrs writes an empty attribute block.
func (e *encoder) noAttrs() *encoder { return e.u32(0) }

// bytes returns the finished packet with its length.
func (e *encoder) bytes() []byte {
	binary.BigEndian.PutUint32(e.b, uint32(len(e.b)-4)) // #nosec G115 -- a request packet is a few KiB
	return e.b
}

// decoder reads a packet body. The first error sticks; every read after it
// returns zero values.
type decoder struct {
	b   []byte
	err error
}

func (d *decoder) fail() { d.err = errMalformed; d.b = nil }

func (d *decoder) u32() uint32 {
	if d.err != nil || len(d.b) < 4 {
		d.fail()
		return 0
	}
	v := binary.BigEndian.Uint32(d.b)
	d.b = d.b[4:]
	return v
}

func (d *decoder) u64() uint64 {
	if d.err != nil || len(d.b) < 8 {
		d.fail()
		return 0
	}
	v := binary.BigEndian.Uint64(d.b)
	d.b = d.b[8:]
	return v
}

// bytesN reads a string of at most max bytes without copying.
func (d *decoder) bytesN(max int) []byte {
	n := d.u32()
	if d.err != nil || int64(n) > int64(max) || int64(n) > int64(len(d.b)) {
		d.fail()
		return nil
	}
	v := d.b[:n:n]
	d.b = d.b[n:]
	return v
}

// end requires that nothing follows.
func (d *decoder) end() error {
	if d.err == nil && len(d.b) != 0 {
		d.fail()
	}
	return d.err
}

// attrs reads an attribute block within the bounds of l. Unknown flags,
// more than 16 extensions or more than 64 KiB of extension data fail.
func (d *decoder) attrs(l limits) attrs {
	var a attrs
	a.flags = d.u32()
	if d.err != nil {
		return a
	}
	if a.flags&^attrKnown != 0 {
		d.fail()
		return a
	}
	if a.has(attrSize) {
		a.size = d.u64()
	}
	if a.has(attrUIDGID) {
		a.uid, a.gid = d.u32(), d.u32()
	}
	if a.has(attrPermissions) {
		a.mode = d.u32()
	}
	if a.has(attrACModTime) {
		a.atime, a.mtime = d.u32(), d.u32()
	}
	if !a.has(attrExtended) {
		return a
	}
	count := d.u32()
	if count > maxAttrExtensions {
		d.fail()
		return a
	}
	budget := min(l.maxMetadata, maxAttrExtensionBytes)
	for range count {
		for range 2 {
			v := d.bytesN(l.maxName)
			a.extensions += len(v)
			if d.err != nil || a.extensions > budget {
				d.fail()
				return a
			}
		}
	}
	return a
}

// names reads the members of an SSH_FXP_NAME reply. A count of zero is
// malformed (Python rule). What a name may contain is decided by the
// caller: a directory entry and the answer of REALPATH differ.
func (d *decoder) names(l limits) []nameEntry {
	count := d.u32()
	if d.err != nil || count == 0 || int64(count) > int64(len(d.b))/12 {
		// 12 bytes is the smallest member: two empty strings and flags.
		d.fail()
		return nil
	}
	out := make([]nameEntry, 0, count)
	for range count {
		name := d.bytesN(l.maxName)
		long := d.bytesN(l.maxName)
		a := d.attrs(l)
		if d.err != nil {
			return nil
		}
		out = append(out, nameEntry{name: string(name), longname: len(long), attrs: a})
	}
	return out
}

// status is a decoded SSH_FXP_STATUS. The message is remote text and is
// never shown; only its length is checked.
type status struct{ code uint32 }

func (d *decoder) status(l limits) status {
	s := status{code: d.u32()}
	if d.err != nil {
		return s
	}
	if len(d.b) == 0 {
		// Some servers omit message and language tag (v3 allows it).
		return s
	}
	d.bytesN(l.maxName)
	d.bytesN(l.maxName)
	return s
}

// handle reads an SSH_FXP_HANDLE body within SFTP_MAX_HANDLE_BYTES.
func (d *decoder) handle(l limits) string {
	h := d.bytesN(l.maxHandle)
	if d.err == nil && len(h) == 0 {
		d.fail()
	}
	return string(h)
}

// parseVersion reads SSH_FXP_VERSION with the rules of the Python
// release (BoundedSFTPClient): only version 3 has extensions; a pair
// whose name or data is empty or longer than 256 bytes, more than 64
// pairs, a truncated pair or a name announced twice with different data
// leave no extension at all; a name that is not ASCII is skipped.
func parseVersion(body []byte) (uint32, map[string]string, error) {
	if len(body) < 4 {
		return 0, nil, errMalformed
	}
	v := binary.BigEndian.Uint32(body)
	ext := map[string]string{}
	rest := body[4:]
	for pairs := 0; len(rest) > 0; pairs++ {
		if pairs >= maxVersionExtensions {
			return v, map[string]string{}, nil
		}
		var pair [2][]byte
		for i := range pair {
			if len(rest) < 4 {
				return v, map[string]string{}, nil
			}
			n := binary.BigEndian.Uint32(rest)
			rest = rest[4:]
			if n == 0 || n > maxVersionExtensionBytes || int64(n) > int64(len(rest)) {
				return v, map[string]string{}, nil
			}
			pair[i], rest = rest[:n], rest[n:]
		}
		if !ascii(pair[0]) || !ascii(pair[1]) {
			continue
		}
		name, data := string(pair[0]), string(pair[1])
		if old, ok := ext[name]; ok && old != data {
			return v, map[string]string{}, nil
		}
		ext[name] = data
	}
	if v != 3 {
		return v, map[string]string{}, nil
	}
	return v, ext, nil
}

func ascii(b []byte) bool {
	for _, c := range b {
		if c >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// validateReply checks a reply to a pkg/sftp request before it is passed
// on: the metadata bounds that x/crypto and pkg/sftp do not enforce. body
// starts after the request id.
func validateReply(typ byte, body []byte, l limits) error {
	d := &decoder{b: body}
	switch typ {
	case fxpStatus:
		d.status(l)
	case fxpHandle:
		d.handle(l)
	case fxpName:
		d.names(l)
	case fxpAttrs:
		d.attrs(l)
	case fxpData:
		d.bytesN(len(body))
	case fxpExtReply:
		return nil
	default:
		return errMalformed
	}
	return d.end()
}
