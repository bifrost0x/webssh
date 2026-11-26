package vault

import (
	"bytes"
	"encoding/binary"
)

// openSSHInfo is what the unencrypted header of an "openssh-key-v1"
// container says about the key, read before anything is decrypted.
type openSSHInfo struct {
	keyType string // type of the first public key, e.g. "ssh-ed25519"
	rounds  uint32 // bcrypt rounds; 0 for an unencrypted key
}

// inspectOpenSSH reads the header of an OpenSSH private key container
// (PROTOCOL.key: magic, cipher, KDF name, KDF options, key count, public
// keys). ok is false when the data is not such a container; the parser
// then reports the format error itself.
func inspectOpenSSH(data []byte) (info openSSHInfo, ok bool) {
	rest, ok := bytes.CutPrefix(data, []byte("openssh-key-v1\x00"))
	if !ok {
		return info, false
	}
	var kdfName, kdfOptions []byte
	if _, rest, ok = readString(rest); !ok { // cipher
		return info, false
	}
	if kdfName, rest, ok = readString(rest); !ok {
		return info, false
	}
	if kdfOptions, rest, ok = readString(rest); !ok {
		return info, false
	}
	if string(kdfName) == "bcrypt" {
		_, opts, ok := readString(kdfOptions) // salt
		if !ok || len(opts) < 4 {
			return info, false
		}
		info.rounds = binary.BigEndian.Uint32(opts)
	}
	if len(rest) < 4 || binary.BigEndian.Uint32(rest) == 0 {
		return info, false
	}
	blob, _, ok := readString(rest[4:])
	if !ok {
		return info, false
	}
	name, _, ok := readString(blob)
	if !ok {
		return info, false
	}
	info.keyType = string(name)
	return info, true
}

// readString reads one SSH wire-format string (uint32 length, bytes).
func readString(b []byte) (value, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(b)
	if int64(n) > int64(len(b)-4) {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}
