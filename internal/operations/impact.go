package operations

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	json "encoding/json/v2"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/principal"
)

// Credential is one sign-in credential or factor of an account,
// identified by its row id and creation time.
type Credential struct {
	ID        int64  `json:"id"`
	CreatedAt string `json:"created_at"`
}

// Account is what the impact preview needs to know about an account.
type Account struct {
	ID         int64        `json:"id"`
	CreatedAt  string       `json:"created_at"`
	Username   string       `json:"username"`
	Generation int64        `json:"generation"`
	Admin      bool         `json:"admin"`
	Locked     bool         `json:"locked"`
	MFA        bool         `json:"mfa"`
	Password   bool         `json:"password"`
	Passkey    []Credential `json:"passkey"`
	TOTP       []Credential `json:"totp"`
	Recovery   []Credential `json:"recovery"`
	OIDC       []Credential `json:"oidc"`
	LDAP       *Credential  `json:"ldap"`
	GitHub     *Credential  `json:"github"`
}

func (a Account) has(feature string) bool {
	switch feature {
	case "password":
		return a.Password
	case "passkey":
		return len(a.Passkey) > 0
	case "totp":
		return len(a.TOTP) > 0
	case "recovery":
		return len(a.Recovery) > 0
	case "oidc":
		return len(a.OIDC) > 0
	case "ldap":
		return a.LDAP != nil
	case "github":
		return a.GitHub != nil
	}
	return false
}

// Inventory lists every account with its credentials (provided by the
// composition root from internal/accounts and the factor packages).
// GitHubActive says whether GitHub sign-in is active.
type Inventory interface {
	Accounts(ctx context.Context) ([]Account, error)
	GitHubActive(ctx context.Context) (bool, error)
}

// AccountImpact is one affected account.
type AccountImpact struct {
	Username         string   `json:"username"`
	Admin            bool     `json:"admin"`
	Locked           bool     `json:"locked"`
	MFARequired      bool     `json:"mfa_required"`
	RemainingPrimary []string `json:"remaining_primary"`
	RemainingFactors []string `json:"remaining_factors"`
}

// Impact is the preview of turning a feature off.
type Impact struct {
	Feature                       string          `json:"feature"`
	Active                        bool            `json:"active"`
	AffectedAccounts              int             `json:"affected_accounts"`
	AffectedAdmins                int             `json:"affected_admins"`
	LockedAffectedAccounts        int             `json:"locked_affected_accounts"`
	RemainingPrimary              map[string]int  `json:"remaining_primary"`
	RemainingFactors              map[string]int  `json:"remaining_factors"`
	AccountsWithoutPrimary        int             `json:"accounts_without_primary"`
	AdminsWithoutPrimary          int             `json:"admins_without_primary"`
	MFARequiredWithoutLocalFactor int             `json:"mfa_required_without_local_factor"`
	AdminsWithoutLocalFactor      int             `json:"admins_without_local_factor"`
	Tested                        bool            `json:"tested"`
	Accounts                      []AccountImpact `json:"accounts"`
}

// snapshot computes the impact of turning feature off and a digest of
// everything it depends on (_snapshot): every gate and every account
// with its credentials, so an approval breaks when any of them changes.
func (g *Gates) snapshot(ctx context.Context, inv Inventory, feature string) (string, Impact, error) {
	gates, err := g.All(ctx)
	if err != nil {
		return "", Impact{}, err
	}
	accounts, err := inv.Accounts(ctx)
	if err != nil {
		return "", Impact{}, err
	}
	githubActive, err := inv.GitHubActive(ctx)
	if err != nil {
		return "", Impact{}, err
	}
	raw, err := json.Marshal(map[string]any{"gates": gates, "github_active": githubActive, "accounts": accounts}, json.Deterministic(true))
	if err != nil {
		return "", Impact{}, err
	}
	sum := sha256.Sum256(raw)
	active := map[string]bool{}
	var current Status
	for _, s := range gates {
		active[s.Name] = s.Active && s.Name != feature
		if s.Name == feature {
			current = s
		}
	}
	im := Impact{Feature: feature, Active: current.Active, RemainingPrimary: map[string]int{}, RemainingFactors: map[string]int{}, Accounts: []AccountImpact{}}
	for _, a := range accounts {
		if !a.has(feature) {
			continue
		}
		var primary, factors []string
		for _, n := range []string{"password", "passkey", "oidc", "ldap", "github"} {
			usable := n == "password" || (n == "github" && githubActive) || active[n]
			if a.has(n) && usable && (n != "oidc" || a.LDAP == nil) {
				primary = append(primary, n)
			}
		}
		for _, n := range []string{"passkey", "totp", "recovery"} {
			if a.has(n) && active[n] {
				factors = append(factors, n)
			}
		}
		im.AffectedAccounts++
		im.AffectedAdmins += b2i(a.Admin)
		im.LockedAffectedAccounts += b2i(a.Locked)
		im.Accounts = append(im.Accounts, AccountImpact{Username: a.Username, Admin: a.Admin, Locked: a.Locked, MFARequired: a.MFA,
			RemainingPrimary: nonNil(primary), RemainingFactors: nonNil(factors)})
		if a.Locked {
			continue
		}
		for _, n := range primary {
			im.RemainingPrimary[n]++
		}
		for _, n := range factors {
			im.RemainingFactors[n]++
		}
		if len(primary) == 0 {
			im.AccountsWithoutPrimary++
			im.AdminsWithoutPrimary += b2i(a.Admin)
		}
		if a.MFA && !slices.Contains(factors, "passkey") && !slices.Contains(factors, "totp") {
			im.MFARequiredWithoutLocalFactor++
			im.AdminsWithoutLocalFactor += b2i(a.Admin)
		}
	}
	return hex.EncodeToString(sum[:]), im, nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// approvalTTL is the lifetime of an impact approval (max_age=300).
const approvalTTL = 5 * time.Minute

// MAC is the part of the keyring the approvals use.
type MAC interface {
	MAC(p keyring.Purpose, msg []byte) []byte
}

func approvalMAC(m MAC, feature string, p principal.Principal, issued int64, digest string) string {
	msg := strings.Join([]string{"webssh-feature-impact-v1", feature, strconv.FormatInt(p.UserID, 10), p.SessionID, strconv.FormatInt(issued, 10), digest}, "\x00")
	return hex.EncodeToString(m.MAC(keyring.StepUpGrant, []byte(msg)))
}

// approval binds a preview to the feature, the administrator, the exact
// session and the state digest, for five minutes.
func approval(m MAC, feature string, p principal.Principal, now time.Time, digest string) string {
	issued := now.Unix()
	return "v1." + strconv.FormatInt(issued, 10) + "." + approvalMAC(m, feature, p, issued, digest)
}

func approvalValid(m MAC, token, feature string, p principal.Principal, now time.Time, digest string) bool {
	if len(token) > 2048 {
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return false
	}
	issued, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || issued > now.Unix() || now.Unix()-issued > int64(approvalTTL/time.Second) {
		return false
	}
	return hmac.Equal([]byte(parts[2]), []byte(approvalMAC(m, feature, p, issued, digest)))
}
