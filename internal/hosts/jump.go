package hosts

import (
	"context"
	"encoding/json/jsontext"
	"fmt"
	"slices"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/store"
)

// usageDetailLimit is _JUMP_HOST_USAGE_DETAIL_LIMIT and its SOCKS twin.
const usageDetailLimit = 20

// JumpHosts returns the jump hosts of owner (list_jump_hosts).
func (s *Service) JumpHosts(ctx context.Context, owner int64) ([]jsontext.Value, error) {
	return s.list(ctx, jumpTable, owner, "Failed to load jump hosts")
}

// SOCKSProxies returns the SOCKS5 proxies of owner (list_socks_proxies).
func (s *Service) SOCKSProxies(ctx context.Context, owner int64) ([]jsontext.Value, error) {
	return s.list(ctx, socksTable, owner, "Failed to load SOCKS proxies")
}

func (s *Service) list(ctx context.Context, t table, owner int64, message string) ([]jsontext.Value, error) {
	var records []record
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		records, err = load(ctx, tx, t, owner)
		return err
	})
	if err != nil {
		return nil, classify(err, message)
	}
	return encodeAll(records), nil
}

// SaveJumpHost creates or updates a jump host (add_jump_host). It never
// stores a password.
func (s *Service) SaveJumpHost(ctx context.Context, owner int64, req protocol.HostsJumpSave) (jsontext.Value, error) {
	return s.saveJumpHost(ctx, owner, req, nil)
}

func (s *Service) saveJumpHost(ctx context.Context, owner int64, req protocol.HostsJumpSave, then Created) (jsontext.Value, error) {
	port := req.Port
	if len(port) == 0 {
		port = jsonInt(22) // the handler's default
	}
	if !truthy(req.Name) || !truthy(req.Host) || !truthy(req.Username) || !truthy(req.AuthType) {
		return nil, invalid("Missing required fields")
	}
	name, ok := asString(req.Name)
	if !ok || pyStrip(name) == "" {
		return nil, invalid("Invalid jump host name")
	}
	host, ok := asString(req.Host)
	host = pyStrip(host)
	if !ok || !validHost(host) {
		return nil, invalid("Invalid host format")
	}
	number := int64(22)
	if !isNull(port) && string(port) != `""` {
		n, ok := pyInt(port)
		if !ok {
			return nil, invalid("Invalid port number")
		}
		number = n
	}
	if number < 1 || number > 65535 {
		return nil, invalid("Port must be between 1 and 65535")
	}
	username, ok := asString(req.Username)
	username = pyStrip(username)
	if !ok || !validUsername(username) {
		return nil, invalid("Invalid username format")
	}
	authType, _ := asString(req.AuthType)
	if authType != "password" && authType != "key" {
		return nil, invalid("Invalid auth_type")
	}
	if authType == "key" && !truthy(req.KeyID) {
		return nil, invalid("key_id required for key authentication")
	}
	keyID, keyIsText := asString(req.KeyID)
	if len(req.KeyID) > 0 && !isNull(req.KeyID) && !keyIsText {
		return nil, invalid("Invalid key reference")
	}
	if authType == "key" {
		if err := s.checkKey(ctx, owner, keyID); err != nil {
			return nil, err
		}
	}
	if len(req.LegacyAlgorithms) > 0 && !isBool(req.LegacyAlgorithms) {
		return nil, invalid("legacy_algorithms must be a boolean")
	}
	var r record
	r.set("id", jsonString(s.newID()))
	r.set("name", jsonString(pyPrefix(pyStrip(name), 128)))
	r.set("host", jsonString(host))
	r.set("port", jsonInt(number))
	r.set("username", jsonString(username))
	r.set("auth_type", jsonString(authType))
	r.set("key_id", jsonNull)
	if authType == "key" {
		r.set("key_id", jsonString(keyID))
	}
	r.set("created_at", jsonString(isoNaive(s.now())))
	if string(req.LegacyAlgorithms) == "true" {
		r.set("legacy_algorithms", jsonTrue)
	}
	if err := checkBudgets(&r, nil, jumpBudgets, true); err != nil {
		return nil, err
	}
	update := len(req.JumpHostID) > 0 && !isNull(req.JumpHostID)
	err := s.DB.Write(ctx, func(tx *store.Tx) error {
		all, err := loadStores(ctx, tx, owner)
		if err != nil {
			return err
		}
		next, err := upsertRecord(all["jump_hosts"], &r, update, req.JumpHostID, errJumpNotFound)
		if err != nil {
			return err
		}
		if err := checkNameFree(all["jump_hosts"], ownPositions(all["jump_hosts"], update, req.JumpHostID), r.text("name"), errDuplicateJumpName); err != nil {
			return err
		}
		if !validJumpHost(&r) {
			return fault.New(fault.ValidationError, "Failed to save jump host")
		}
		if err := checkGrowth(s.Limits, jumpKind, all, next); err != nil {
			return err
		}
		if err := replace(ctx, tx, jumpTable, owner, next); err != nil {
			return err
		}
		return runCreated(ctx, tx, then, r)
	})
	if err != nil {
		return nil, classify(err, "Failed to save jump host")
	}
	return r.encode(), nil
}

// upsertRecord appends r, or with update replaces every record with the
// requested ID, keeping its ID and creation time (Python replaces all
// matches, the first one decides).
func upsertRecord(records []record, r *record, update bool, requested jsontext.Value, notFound error) ([]record, error) {
	next := slices.Clone(records)
	if !update {
		return append(next, *r), nil
	}
	id, ok := asString(requested)
	index := -1
	if ok {
		index = find(records, id)
	}
	if index < 0 {
		return nil, notFound
	}
	existing := &records[index]
	r.set("id", jsonString(id))
	if created, ok := existing.get("created_at"); ok {
		r.set("created_at", created)
	}
	for i := range next {
		if v, ok := next[i].str("id"); ok && v == id {
			next[i] = *r
		}
	}
	return next, nil
}

// DeleteJumpHost removes a jump host no saved host uses
// (delete_jump_host).
func (s *Service) DeleteJumpHost(ctx context.Context, owner int64, jumpHostID jsontext.Value) error {
	if !truthy(jumpHostID) {
		return invalid("Jump host ID required")
	}
	err := s.DB.Write(ctx, func(tx *store.Tx) error {
		profiles, err := load(ctx, tx, profileTable, owner)
		if err != nil {
			return err
		}
		if err := inUse(profiles, "jump_host_id", jumpHostID, "Jump host"); err != nil {
			return err
		}
		return deleteRecord(ctx, tx, jumpTable, owner, jumpHostID, errJumpNotFound)
	})
	return classify(err, "Failed to delete jump host")
}

func deleteRecord(ctx context.Context, tx *store.Tx, t table, owner int64, id jsontext.Value, notFound error) error {
	records, err := load(ctx, tx, t, owner)
	if err != nil {
		return err
	}
	index := -1
	if s, ok := asString(id); ok {
		index = find(records, s)
	}
	if index < 0 {
		return notFound
	}
	return replace(ctx, tx, t, owner, slices.Delete(slices.Clone(records), index, index+1))
}

// inUse is the usage summary of a jump host or SOCKS5 proxy: the number of
// saved hosts that reference it and the names of the first twenty.
func inUse(profiles []record, field string, id jsontext.Value, what string) error {
	id, err := canonical(id)
	if err != nil {
		return err
	}
	count := 0
	var usages []string
	for i := range profiles {
		if v, ok := profiles[i].get(field); !ok || string(v) != string(id) {
			continue
		}
		count++
		if len(usages) < usageDetailLimit {
			usages = append(usages, safeReferenceName(profiles[i].text("name")))
		}
	}
	if count == 0 {
		return nil
	}
	return usageError(fmt.Sprintf("%s is used by %d %s%s", what, count, plural(count, "profile"), shown(count, len(usages))), usages)
}

func plural(n int, noun string) string {
	if n == 1 {
		return noun
	}
	return noun + "s"
}

func shown(count, listed int) string {
	if count > listed {
		return fmt.Sprintf(" (showing first %d)", listed)
	}
	return ""
}

func usageError(message string, usages []string) error {
	return &fault.Error{Code: fault.InUse, Message: message, Details: map[string]any{"usages": usages}}
}
