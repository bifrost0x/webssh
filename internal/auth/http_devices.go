package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	json "encoding/json/v2"
	"net/http"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/keyring"
)

// Known devices (login_devices.py). After a successful password step the
// browser receives a cookie that names the account and a keyed digest of
// the submitted name. A later password attempt for the same name that
// presents a valid cookie skips the per-name ceiling across all sources,
// so a sender spread over many sources cannot keep the owner out of a
// browser that signed in before; the per-source limit still applies. Its
// failures spend the cookie's own budget instead, after which it counts
// as no cookie. The cookie is bound to the account's auth_generation, so
// a password change, lock or MFA reset ends every issued cookie.
const (
	DeviceMaxAge        = 90 * 24 * time.Hour
	DeviceFailureBudget = 5
	DeviceFailureWindow = time.Hour

	devicePrefix   = "v1."
	deviceDomain   = "webssh-login-device-v1\x00"
	usernameDomain = "webssh-login-username-v1\x00"
	maxDeviceBytes = 1024
)

// DeviceCookie writes the known-device cookie (httpapi.DeviceCookie).
type DeviceCookie interface {
	Name() string
	Set(w http.ResponseWriter, value string, expires time.Time)
}

// DeviceAccounts reads the standing the cookie is bound to
// (internal/accounts).
type DeviceAccounts interface {
	Get(ctx context.Context, id int64) (accounts.Account, error)
}

// Devices issues and checks known-device cookies. The MAC uses the
// keyring purpose of session tokens with its own domain, like the pending
// sign-ins; the Python cookies (itsdangerous) are not read, so a browser
// is known again after its first sign-in with the Go release.
type Devices struct {
	MAC      MAC
	Cookie   DeviceCookie
	Accounts DeviceAccounts
	Now      func() time.Time
}

type devicePayload struct {
	Username string `json:"u"`
	UserID   int64  `json:"i"`
	Gen      int64  `json:"g"`
	Nonce    string `json:"n"`
	Issued   int64  `json:"t"`
}

func (d *Devices) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// UsernameDigest is the keyed digest of a submitted name: trimmed and
// case-folded, so the cookie and the limiter keys carry no readable name.
func (d *Devices) UsernameDigest(name string) string {
	return hex.EncodeToString(d.MAC.MAC(keyring.SessionToken, []byte(usernameDomain+accounts.FoldName(strings.TrimSpace(name)))))
}

func (d *Devices) sign(body string) string {
	return base64.RawURLEncoding.EncodeToString(d.MAC.MAC(keyring.SessionToken, []byte(deviceDomain+body)))
}

// encode returns the cookie value of p.
func (d *Devices) encode(p devicePayload) string {
	raw, _ := json.Marshal(p)
	body := base64.RawURLEncoding.EncodeToString(raw)
	return devicePrefix + body + "." + d.sign(body)
}

// decode verifies a cookie value and returns its payload. It checks the
// MAC and the age; the account is checked by the caller.
func (d *Devices) decode(value string) (devicePayload, bool) {
	var p devicePayload
	if len(value) > maxDeviceBytes || !strings.HasPrefix(value, devicePrefix) {
		return p, false
	}
	body, sig, ok := strings.Cut(value[len(devicePrefix):], ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(d.sign(body))) {
		return p, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil || json.Unmarshal(raw, &p) != nil || p.Username == "" || p.Nonce == "" || p.UserID <= 0 {
		return devicePayload{}, false
	}
	issued := time.Unix(p.Issued, 0)
	now := d.now()
	if issued.After(now.Add(time.Minute)) || now.Sub(issued) > DeviceMaxAge {
		return devicePayload{}, false
	}
	return p, true
}

// Trusted returns the nonce of a valid known-device cookie of r for the
// submitted name, or "". The cookie must be well signed, younger than
// DeviceMaxAge, issued for this name, and its account must exist, be
// unlocked and still have the generation it was issued under. Anything
// else counts as no cookie.
func (d *Devices) Trusted(r *http.Request, username string) string {
	if d == nil || strings.TrimSpace(username) == "" {
		return ""
	}
	p, ok := d.presented(r)
	if !ok || !hmac.Equal([]byte(p.Username), []byte(d.UsernameDigest(username))) {
		return ""
	}
	return p.Nonce
}

// presented returns the payload of a valid cookie of r: well signed,
// younger than DeviceMaxAge, and its account exists, is unlocked and
// still has the generation the cookie was issued under.
func (d *Devices) presented(r *http.Request) (devicePayload, bool) {
	c, err := r.Cookie(d.Cookie.Name())
	if err != nil {
		return devicePayload{}, false
	}
	p, ok := d.decode(c.Value)
	if !ok {
		return devicePayload{}, false
	}
	acc, err := d.Accounts.Get(r.Context(), p.UserID)
	if err != nil || acc.IsLocked || acc.AuthGeneration != p.Gen {
		return devicePayload{}, false
	}
	return p, true
}

// Presented returns the name digest of a valid cookie r holds for the
// account userID, or "" (presented_device_digest). Read it before the
// account's generation changes and pass it to Reissue afterwards, so a
// browser that stays signed in keeps its exemption.
func (d *Devices) Presented(r *http.Request, userID int64) string {
	if d == nil {
		return ""
	}
	p, ok := d.presented(r)
	if !ok || p.UserID != userID {
		return ""
	}
	return p.Username
}

// Reissue issues a fresh cookie for the name digest under the account's
// current generation; an empty digest issues nothing (reissue_device).
func (d *Devices) Reissue(w http.ResponseWriter, acc accounts.Account, digest string) {
	if d == nil || digest == "" {
		return
	}
	d.issue(w, acc, digest)
}

// Remember issues a fresh cookie for the submitted name with the response
// of a successful password step.
func (d *Devices) Remember(w http.ResponseWriter, acc accounts.Account, username string) {
	if d == nil {
		return
	}
	d.issue(w, acc, d.UsernameDigest(username))
}

func (d *Devices) issue(w http.ResponseWriter, acc accounts.Account, digest string) {
	var nonce [16]byte
	_, _ = rand.Read(nonce[:]) // crypto/rand.Read never fails
	now := d.now()
	d.Cookie.Set(w, d.encode(devicePayload{Username: digest, UserID: acc.ID, Gen: acc.AuthGeneration,
		Nonce: base64.RawURLEncoding.EncodeToString(nonce[:]), Issued: now.Unix()}), now.Add(DeviceMaxAge))
}

// DeviceBudgetKey is the limiter key of a cookie's failure budget.
func DeviceBudgetKey(endpoint, nonce string) string {
	return endpoint + ":device:" + nonce
}
