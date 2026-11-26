package keyring

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// BrowserScope returns the namespace of a user's browser-local data
// (recent connections, favourites, scrollback, topology layout). It is the
// derivation of the Python release kept bit for bit (ADR 0007, D-10):
// HMAC-SHA256 keyed with SECRET_KEY alone over
// "webssh-connection-history-v1" NUL id NUL username NUL generation, as
// lower-case hex. generation is the account's incarnation (the ISO form of
// created_at), or its password hash for accounts without created_at.
// It does not use the keyring material, so browsers keep their data across
// the upgrade.
func (r *Ring) BrowserScope(userID int64, username, generation string) string {
	msg := strings.Join([]string{
		"webssh-connection-history-v1",
		strconv.FormatInt(userID, 10),
		username,
		generation,
	}, "\x00")
	m := hmac.New(sha256.New, r.secret)
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}
