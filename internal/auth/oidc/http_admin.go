package oidc

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

var pathInt = regexp.MustCompile(`^(0|[1-9][0-9]{0,17})$`)

// pathID reads a non-negative integer path value as Flask's int
// converter does; anything else is a 404.
func pathID(r *http.Request, name string) (int64, bool) {
	v := r.PathValue(name)
	if !pathInt.MatchString(v) {
		return 0, false
	}
	n, err := strconv.ParseInt(v, 10, 64)
	return n, err == nil
}

// adminTarget reads the account of an administrator route after the
// administrator check; it answers 404 for an unknown account.
func (h *HTTP) adminTarget(w http.ResponseWriter, r *http.Request) (principal.Principal, Account, bool) {
	p, err := principal.RequireAdmin(r.Context())
	if err != nil {
		auth.WriteError(w, r, h.Logger, err)
		return p, Account{}, false
	}
	userID, ok := pathID(r, "user_id")
	if !ok {
		http.NotFound(w, r)
		return p, Account{}, false
	}
	acc, err := h.Accounts.OIDCAccount(r.Context(), userID)
	if fault.Is(err, fault.NotFound) {
		errorJSON(w, http.StatusNotFound, "User not found")
		return p, Account{}, false
	}
	if err != nil {
		auth.WriteError(w, r, h.Logger, err)
		return p, Account{}, false
	}
	return p, acc, true
}

func (h *HTTP) adminList(w http.ResponseWriter, r *http.Request) {
	if _, acc, ok := h.adminTarget(w, r); ok {
		h.identities(w, r, acc.ID, true)
	}
}

// consumeAdmin spends the step-up grant of an administrator route before
// anything else of the request is read, as step_up_required does.
func (h *HTTP) consumeAdmin(w http.ResponseWriter, r *http.Request, action principal.Action, target string) bool {
	p, err := principal.RequireAdmin(r.Context())
	if err == nil {
		err = h.StepUp.Consume(r.Context(), p, action, target, r.Header.Get(auth.StepUpHeader))
	}
	if err != nil {
		auth.WriteError(w, r, h.Logger, err)
		return false
	}
	return true
}

// adminLink links a subject of the configured issuer to an account
// (oidc.link). LDAP- and GitHub-managed accounts are refused.
func (h *HTTP) adminLink(w http.ResponseWriter, r *http.Request) {
	userID, ok := pathID(r, "user_id")
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !h.consumeAdmin(w, r, principal.ActionOIDCLink, strconv.FormatInt(userID, 10)) {
		return
	}
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	p, acc, ok := h.adminTarget(w, r)
	if !ok {
		return
	}
	if acc.Managed != "" {
		errorJSON(w, http.StatusBadRequest, "OIDC identities cannot be linked to externally managed accounts")
		return
	}
	if name, _ := body.String("confirm_username"); name != acc.Username {
		errorJSON(w, http.StatusBadRequest, "Target confirmation does not match")
		return
	}
	subject, isString := body.String("subject")
	subject = strings.TrimSpace(subject)
	if !isString || subject == "" || utf8.RuneCountInString(subject) > maxIdentifierRunes {
		errorJSON(w, http.StatusBadRequest, "OIDC subject is required")
		return
	}
	li, err := h.Links.Link(r.Context(), acc.ID, auth.Identity{Provider: auth.ProviderOIDC, Issuer: h.Provider.Issuer(), Subject: subject})
	switch {
	case fault.Is(err, fault.Conflict):
		errorJSON(w, http.StatusConflict, msgLinked)
		return
	case err != nil:
		h.audit("OIDC_IDENTITY_STORAGE_FAILED", "admin", p.Username, "user", acc.Username)
		h.logger().ErrorContext(r.Context(), "OIDC identity not stored", "error", err)
		errorJSON(w, http.StatusServiceUnavailable, msgStorage)
		return
	}
	h.audit("OIDC_IDENTITY_LINKED", "admin", p.Username, "user", acc.Username, "issuer", li.Issuer)
	auth.WriteJSON(w, http.StatusCreated, map[string]any{"id": li.ID})
}

// adminUnlink removes an identity (oidc.unlink) and ends the account's
// sessions signed in through it; an administrator unlinking an own
// identity keeps the current browser signed in.
func (h *HTTP) adminUnlink(w http.ResponseWriter, r *http.Request) {
	userID, ok1 := pathID(r, "user_id")
	identityID, ok2 := pathID(r, "identity_id")
	if !ok1 || !ok2 {
		http.NotFound(w, r)
		return
	}
	if !h.consumeAdmin(w, r, principal.ActionOIDCUnlink, strconv.FormatInt(userID, 10)+":"+strconv.FormatInt(identityID, 10)) {
		return
	}
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	p, acc, ok := h.adminTarget(w, r)
	if !ok {
		return
	}
	if name, _ := body.String("confirm_username"); name != acc.Username {
		errorJSON(w, http.StatusBadRequest, "Target confirmation does not match")
		return
	}
	ctx := r.Context()
	except := ""
	if acc.ID == p.UserID {
		except = p.SessionID
	}
	// Sessions that signed in through the identity must not outlive it:
	// they end in the same transaction.
	var revs []principal.Revocation
	err := h.Links.DB.Write(ctx, func(tx *store.Tx) error {
		if err := h.Links.UnlinkTx(ctx, tx, acc.ID, identityID); err != nil {
			return err
		}
		var err error
		revs, err = h.Sessions.RevokeUserTx(ctx, tx, acc.ID, principal.ReasonFactorChanged, except)
		return err
	})
	switch {
	case fault.Is(err, fault.NotFound):
		errorJSON(w, http.StatusNotFound, "OIDC identity not found")
		return
	case err != nil:
		h.audit("OIDC_IDENTITY_STORAGE_FAILED", "admin", p.Username, "user", acc.Username)
		h.logger().ErrorContext(ctx, "OIDC identity not removed", "error", err)
		errorJSON(w, http.StatusServiceUnavailable, msgStorage)
		return
	}
	h.Sessions.Publish(revs)
	h.audit("OIDC_IDENTITY_UNLINKED", "admin", p.Username, "user", acc.Username, "identity_id", identityID)
	auth.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// readBody reads a JSON object body; anything else is 400 "Invalid
// request" (request.get_json(silent=True) not a dict).
func readBody(w http.ResponseWriter, r *http.Request) (auth.Object, bool) {
	body := auth.ReadObject(w, r)
	if len(body) == 0 {
		errorJSON(w, http.StatusBadRequest, "Invalid request")
		return nil, false
	}
	return body, true
}
