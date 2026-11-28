package github

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

var nonName = regexp.MustCompile(`[^a-z0-9_]+`)

// randomAttempts is the number of random names tried after the three
// derived ones (_provision_username).
const randomAttempts = 8

// nameBase is the base of _provision_username: the lower-cased login with
// every run of other characters replaced by "_", stripped of "_", at most
// 32 characters, "github" when nothing is left.
func nameBase(login string) string {
	base := strings.Trim(nonName.ReplaceAllString(pyLower(login), "_"), "_")
	if base == "" {
		base = "github"
	}
	return truncate(base, 32)
}

// truncate is s[:n] for an ASCII string.
func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func lastDigits(id string, n int) string {
	if len(id) > n {
		return id[len(id)-n:]
	}
	return id
}

// nameCandidates are the names _provision_username tries in order.
func nameCandidates(login, githubUserID string, random func() string) []string {
	base := nameBase(login)
	out := []string{
		base,
		truncate(truncate(base, 20)+"_gh"+lastDigits(githubUserID, 8), 32),
		truncate("github_"+githubUserID, 32),
	}
	for range randomAttempts {
		out = append(out, truncate("gh_"+lastDigits(githubUserID, 8)+"_"+random(), 32))
	}
	return out
}

func randomHex3() string {
	var b [3]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails
	return hex.EncodeToString(b[:])
}

var (
	errProvisionFailed = fault.New(fault.Conflict, "GitHub account could not be provisioned")
	errFirstAccount    = fault.New(fault.Forbidden, auth.MsgFirstAccountHost)
)

// provision creates a GitHub-managed account with its identity in one
// transaction (_auto_provision). The account is never an administrator
// and has no local password. A taken name moves on to the next candidate;
// a candidate the account rules refuse (for example a login of one or two
// characters) does too, where the Python release failed the sign-in.
// notFirst refuses the account when it would be the first one
// (errFirstAccount), atomically with the check.
func (s *Service) provision(ctx context.Context, p Profile, notFirst bool) (Identity, error) {
	var out Identity
	err := s.DB.Write(ctx, func(tx *store.Tx) error {
		if notFirst {
			has, err := s.Accounts.HasAccountsTx(ctx, tx)
			if err != nil {
				return err
			}
			if !has {
				return errFirstAccount
			}
		}
		if _, found, err := byGitHubTx(ctx, tx, p.UserID); err != nil || found {
			if found {
				return errProvisionFailed
			}
			return err
		}
		for _, name := range nameCandidates(p.Login, p.UserID, randomHex3) {
			userID, err := s.Accounts.ProvisionTx(ctx, tx, name, "github")
			if fault.Is(err, fault.Conflict) || fault.Is(err, fault.InvalidValue) {
				continue
			}
			if err != nil {
				return err
			}
			out, err = insertTx(ctx, tx, s.newIdentity(userID, p, true))
			out.Login = p.Login
			return err
		}
		return errProvisionFailed
	})
	if err != nil {
		if errors.Is(err, errFirstAccount) {
			return Identity{}, errFirstAccount
		}
		if fault.Is(err, fault.Conflict) {
			return Identity{}, errProvisionFailed
		}
		return Identity{}, fault.Wrap(fault.StorageError, err, "")
	}
	return out, nil
}
