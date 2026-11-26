package hosts

import (
	"context"
	"encoding/json/jsontext"
	"fmt"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/store"
)

// SaveSOCKSProxy creates or updates a SOCKS5 proxy (add_socks_proxy). A
// proxy with password authentication is stored like in Python; its
// password belongs to the credential store, which this release does not
// build, so connecting through it is refused (Resolve).
func (s *Service) SaveSOCKSProxy(ctx context.Context, owner int64, req protocol.HostsSOCKSSave) (jsontext.Value, error) {
	// The handler's defaults for absent members.
	def := func(v, d jsontext.Value) jsontext.Value {
		if len(v) == 0 {
			return d
		}
		return v
	}
	port := def(req.Port, jsonInt(1080))
	authValue := def(req.AuthType, jsonString("none"))
	userValue := def(req.Username, jsonString(""))
	remoteDNS := def(req.RemoteDNS, jsonTrue)

	name, ok := asString(req.Name)
	if !ok || pyStrip(name) == "" {
		return nil, invalid("Invalid SOCKS proxy name")
	}
	host, ok := asString(req.Host)
	if !ok || !validHost(host) {
		return nil, invalid("Invalid host format")
	}
	host = pyStrip(host)
	number, ok := asInt(port)
	if !ok {
		if !isIntegerToken(port) {
			return nil, invalid("Invalid port number")
		}
		number = 0 // an integer beyond int64 is out of range
	}
	if number < 1 || number > 65535 {
		return nil, invalid("Port must be between 1 and 65535")
	}
	authType, ok := asString(authValue)
	if !ok || (authType != "none" && authType != "password") {
		return nil, invalid("Invalid auth_type")
	}
	username, ok := asString(userValue)
	if !ok {
		return nil, invalid("Invalid SOCKS proxy username")
	}
	if authType == "none" && username != "" {
		return nil, invalid("Username requires password authentication")
	}
	if authType == "password" && username == "" {
		return nil, invalid("Username required for password authentication")
	}
	if !isBool(remoteDNS) {
		return nil, invalid("remote_dns must be a boolean")
	}
	update := len(req.SOCKSProxyID) > 0 && !isNull(req.SOCKSProxyID)
	if update {
		if id, ok := asString(req.SOCKSProxyID); !ok || id == "" || pyLen(id) > 64 {
			return nil, invalid("Invalid SOCKS proxy reference")
		}
	}
	var r record
	r.set("id", jsonString(s.newID()))
	r.set("name", jsonString(pyStrip(name)))
	r.set("host", jsonString(host))
	r.set("port", jsonInt(number))
	r.set("username", jsonString(username))
	r.set("auth_type", jsonString(authType))
	r.set("remote_dns", remoteDNS)
	r.set("created_at", jsonString(isoNaive(s.now())))
	if err := checkBudgets(&r, nil, socksBudgets, false); err != nil {
		return nil, err
	}
	err := s.DB.Write(ctx, func(tx *store.Tx) error {
		all, err := loadStores(ctx, tx, owner)
		if err != nil {
			return err
		}
		next, err := upsertRecord(all["socks_proxies"], &r, update, req.SOCKSProxyID, errSOCKSNotFound)
		if err != nil {
			return err
		}
		if !validSOCKSProxy(&r) {
			return fault.New(fault.InvalidValue, "Failed to save SOCKS proxy")
		}
		if err := checkGrowth(s.Limits, socksKind, all, next); err != nil {
			return err
		}
		return replace(ctx, tx, socksTable, owner, next)
	})
	if err != nil {
		return nil, classify(err, "Failed to save SOCKS proxy")
	}
	return r.encode(), nil
}

// DeleteSOCKSProxy removes a SOCKS5 proxy that neither a saved host nor a
// persistent terminal session uses (delete_socks_proxy).
func (s *Service) DeleteSOCKSProxy(ctx context.Context, owner int64, proxyID jsontext.Value) error {
	id, ok := asString(proxyID)
	if !ok || id == "" || pyLen(id) > 64 {
		return invalid("SOCKS proxy ID required")
	}
	if s.Persistent != nil {
		count, labels, err := s.Persistent.UsingSOCKSProxy(ctx, owner, id)
		if err != nil {
			return fault.Wrap(fault.StorageError, err, "Failed to delete SOCKS proxy")
		}
		if count > 0 {
			if len(labels) > usageDetailLimit {
				labels = labels[:usageDetailLimit]
			}
			return usageError(fmt.Sprintf("SOCKS proxy is used by %d persistent %s", count, plural(count, "session")), labels)
		}
	}
	err := s.DB.Write(ctx, func(tx *store.Tx) error {
		profiles, err := load(ctx, tx, profileTable, owner)
		if err != nil {
			return err
		}
		if err := inUse(profiles, "socks_proxy_id", proxyID, "SOCKS proxy"); err != nil {
			return err
		}
		return deleteRecord(ctx, tx, socksTable, owner, proxyID, errSOCKSNotFound)
	})
	return classify(err, "Failed to delete SOCKS proxy")
}
