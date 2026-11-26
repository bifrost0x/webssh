package stepup

import (
	"context"
	"slices"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/principal"
)

// Bootstrap checks and spends factor bootstrap codes (internal/auth,
// auth.Bootstrap).
type Bootstrap interface {
	Live(ctx context.Context, userID int64, action principal.Action) (bool, error)
	Redeem(ctx context.Context, userID int64, action principal.Action, code string) (bool, error)
}

// offered returns the proofs that can confirm action for p: the methods
// of the account, or, when it has none, an operator's bootstrap code. The
// code needs a GitHub sign-in of this session and a live code for the
// action (_bootstrap_available): the GitHub login and the local code
// together stand in for the factor the account does not have yet.
func (s *Service) offered(ctx context.Context, p principal.Principal, sa SessionAssurance, required auth.Assurance, action principal.Action) ([]string, error) {
	methods, err := s.methods(ctx, p, sa, required)
	if err != nil || len(methods) > 0 || s.Bootstrap == nil || p.Recovery || !slices.Contains(sa.Methods, "github") {
		return methods, err
	}
	live, err := s.Bootstrap.Live(ctx, p.UserID, action)
	if err != nil || !live {
		return nil, err
	}
	return []string{MethodBootstrap}, nil
}

func (s *Service) redeemBootstrap(ctx context.Context, p principal.Principal, in intent, code string) error {
	ok, err := s.Bootstrap.Redeem(ctx, p.UserID, in.action, code)
	if err != nil {
		return err
	}
	if !ok {
		return ErrFailed
	}
	return nil
}
