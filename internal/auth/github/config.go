package github

import (
	"context"
	"database/sql"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// Configuration is the GitHub sign-in configuration as the administration
// shows it (GitHubSettings.public_dict). The client secret is never part
// of it. The JSON members are sorted, as Flask sends them.
type Configuration struct {
	Active           bool     `json:"active"`
	AllowedOrgs      []string `json:"allowed_orgs"`
	AutoProvision    bool     `json:"auto_provision"`
	ClientID         string   `json:"client_id"`
	SecretConfigured bool     `json:"client_secret_configured"`
	Enabled          bool     `json:"enabled"`
	Error            *string  `json:"error"`
	Generation       int64    `json:"generation"`
	RedirectURI      string   `json:"redirect_uri"`
}

// configRow is the stored configuration.
type configRow struct {
	Enabled       bool
	ClientID      string
	Secret        []byte // sealed; nil when none is stored
	RedirectURI   string
	AutoProvision bool
	AllowedOrgs   string // JSON text
	Generation    int64
	UpdatedBy     sql.NullInt64
	UpdatedUS     int64
	SecretUS      sql.NullInt64
}

var secretAAD = keyring.AAD{Table: "authgithub_config", Column: "client_secret", Row: "1"}

func readConfigTx(ctx context.Context, tx *store.Tx) (configRow, bool, error) {
	var c configRow
	err := tx.QueryRowContext(ctx, `SELECT enabled, client_id, client_secret, redirect_uri, auto_provision, allowed_orgs,
		generation, updated_by, updated_us, secret_updated_us FROM authgithub_config WHERE singleton = 1`).
		Scan(&c.Enabled, &c.ClientID, &c.Secret, &c.RedirectURI, &c.AutoProvision, &c.AllowedOrgs,
			&c.Generation, &c.UpdatedBy, &c.UpdatedUS, &c.SecretUS)
	if errors.Is(err, sql.ErrNoRows) {
		return configRow{}, false, nil
	}
	if err != nil {
		return configRow{}, false, fmt.Errorf("github: read configuration: %w", err)
	}
	return c, true, nil
}

func writeConfigTx(ctx context.Context, tx *store.Tx, c configRow) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO authgithub_config (singleton, enabled, client_id, client_secret, redirect_uri,
		auto_provision, allowed_orgs, generation, updated_by, updated_us, secret_updated_us) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (singleton) DO UPDATE SET enabled = excluded.enabled, client_id = excluded.client_id,
		client_secret = excluded.client_secret, redirect_uri = excluded.redirect_uri, auto_provision = excluded.auto_provision,
		allowed_orgs = excluded.allowed_orgs, generation = excluded.generation, updated_by = excluded.updated_by,
		updated_us = excluded.updated_us, secret_updated_us = excluded.secret_updated_us`,
		c.Enabled, c.ClientID, c.Secret, c.RedirectURI, c.AutoProvision, c.AllowedOrgs, c.Generation,
		c.UpdatedBy, c.UpdatedUS, c.SecretUS)
	if err != nil {
		return fmt.Errorf("github: store configuration: %w", err)
	}
	return nil
}

// view is get_settings without the secret.
func (s *Service) view(c configRow, found bool) Configuration {
	if !found {
		return Configuration{AllowedOrgs: []string{}}
	}
	orgs, err := storedOrgs(c.AllowedOrgs)
	msg := errorText(err)
	if orgs == nil {
		orgs = []string{}
	}
	if c.Enabled {
		switch {
		case msg != "":
		case !clientIDPattern.MatchString(c.ClientID):
			msg = msgClientIDInvalid
		case len(c.Secret) == 0:
			msg = msgSecretMissing
		default:
			msg = errorText(validateRedirect(c.RedirectURI, s.Root))
		}
	}
	v := Configuration{Enabled: c.Enabled, ClientID: c.ClientID, SecretConfigured: len(c.Secret) > 0,
		RedirectURI: c.RedirectURI, AutoProvision: c.AutoProvision, AllowedOrgs: orgs, Generation: c.Generation}
	if msg != "" {
		v.Error = &msg
	}
	v.Active = v.Enabled && v.Error == nil
	return v
}

// Configuration returns the stored configuration without its secret.
func (s *Service) Configuration(ctx context.Context) (Configuration, error) {
	var c configRow
	var found bool
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		c, found, err = readConfigTx(ctx, tx)
		return err
	})
	if err != nil {
		return Configuration{}, fault.Wrap(fault.StorageError, err, "")
	}
	return s.view(c, found), nil
}

// Active is github_auth_is_active: GitHub sign-in is enabled and complete.
// A failure to read counts as inactive and is logged.
func (s *Service) Active(ctx context.Context) bool {
	c, err := s.Configuration(ctx)
	if err != nil {
		s.logger().WarnContext(ctx, "GitHub sign-in status could not be determined", "error_type", "StorageError")
		return false
	}
	return c.Active
}

// active returns the configuration with the opened client secret, for a
// sign-in. A secret that does not open is a configuration error.
func (s *Service) active(ctx context.Context) (Configuration, string, error) {
	var c configRow
	var found bool
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		c, found, err = readConfigTx(ctx, tx)
		return err
	})
	if err != nil {
		return Configuration{}, "", fault.Wrap(fault.StorageError, err, "")
	}
	v := s.view(c, found)
	if len(c.Secret) == 0 {
		return v, "", nil
	}
	plain, err := s.Ring.Open(keyring.GitHubClientSecret, secretAAD, c.Secret)
	if err != nil {
		return v, "", configErr("Stored GitHub client secret cannot be decrypted")
	}
	return v, string(plain), nil
}

var errInvalidConfig = fault.New(fault.InvalidRequest, "Invalid GitHub configuration")

// updateKeys are the members an update may carry.
var updateKeys = []string{"enabled", "client_id", "client_secret", "redirect_uri", "auto_provision", "allowed_orgs", "clear_client_secret"}

// Update applies an administrator's change (update_settings) and returns
// the new configuration. Every refusal is "Invalid GitHub configuration";
// nothing is stored then. A stored change ends every GitHub redirect in
// progress.
func (s *Service) Update(ctx context.Context, body []byte, adminID int64) (Configuration, error) {
	var data map[string]jsontext.Value
	if err := decodeJSON(body, &data); err != nil || len(data) == 0 {
		return Configuration{}, errInvalidConfig
	}
	for k := range data {
		if !slices.Contains(updateKeys, k) {
			return Configuration{}, errInvalidConfig
		}
	}
	var out Configuration
	err := s.DB.Write(ctx, func(tx *store.Tx) error {
		c, found, err := readConfigTx(ctx, tx)
		if err != nil {
			return err
		}
		if !found {
			c = configRow{AllowedOrgs: "[]", Generation: 1}
		}
		if err := s.apply(&c, data); err != nil {
			return err
		}
		now := s.now()
		c.UpdatedBy = sql.NullInt64{Int64: adminID, Valid: true}
		c.UpdatedUS = now.UnixMicro()
		c.Generation++
		if err := s.applySecret(&c, data, now.UnixMicro()); err != nil {
			return err
		}
		out = s.view(c, true)
		if c.Enabled && !out.Active {
			return errInvalidConfig
		}
		if err := writeConfigTx(ctx, tx, c); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM authgithub_flights`); err != nil {
			return fmt.Errorf("github: drop flights: %w", err)
		}
		return nil
	})
	if err != nil {
		if fault.Is(err, fault.InvalidRequest) {
			return Configuration{}, err
		}
		return Configuration{}, fault.Wrap(fault.StorageError, err, "GitHub configuration could not be saved")
	}
	return out, nil
}

func member[T any](data map[string]jsontext.Value, key string) (T, bool, error) {
	var v T
	raw, ok := data[key]
	if !ok {
		return v, false, nil
	}
	if err := decodeJSON(raw, &v); err != nil {
		return v, true, errInvalidConfig
	}
	return v, true, nil
}

// apply sets the plain members in the order of update_settings.
func (s *Service) apply(c *configRow, data map[string]jsontext.Value) error {
	for _, key := range []string{"enabled", "auto_provision"} {
		raw, ok := data[key]
		if !ok {
			continue
		}
		if k := raw.Kind(); k != 't' && k != 'f' {
			return errInvalidConfig
		}
		if key == "enabled" {
			c.Enabled = raw.Kind() == 't'
		} else {
			c.AutoProvision = raw.Kind() == 't'
		}
	}
	if id, ok, err := stringMember(data, "client_id"); err != nil {
		return err
	} else if ok {
		id = pyStrip(id)
		if id != "" && !clientIDPattern.MatchString(id) {
			return errInvalidConfig
		}
		c.ClientID = id
	}
	if uri, ok, err := stringMember(data, "redirect_uri"); err != nil {
		return err
	} else if ok {
		uri = pyStrip(uri)
		if uri != "" && validateRedirect(uri, s.Root) != nil {
			return errInvalidConfig
		}
		c.RedirectURI = uri
	}
	if v, ok, err := member[any](data, "allowed_orgs"); err != nil {
		return err
	} else if ok {
		orgs, err := normalizeOrgs(v)
		if err != nil {
			return errInvalidConfig
		}
		c.AllowedOrgs = encodeOrgs(orgs)
	}
	// Production keeps sign-up closed: automatic accounts need an
	// organization limit there.
	if orgs, err := storedOrgs(c.AllowedOrgs); err == nil && s.unrestricted(c.AutoProvision, orgs) {
		return errInvalidConfig
	}
	return nil
}

func stringMember(data map[string]jsontext.Value, key string) (string, bool, error) {
	raw, ok := data[key]
	if !ok {
		return "", false, nil
	}
	if raw.Kind() != '"' {
		return "", true, errInvalidConfig
	}
	v, _, err := member[string](data, key)
	return v, true, err
}

// applySecret clears or replaces the client secret.
func (s *Service) applySecret(c *configRow, data map[string]jsontext.Value, nowUS int64) error {
	if raw, ok := data["clear_client_secret"]; ok {
		if k := raw.Kind(); k != 't' && k != 'f' {
			return errInvalidConfig
		}
		if raw.Kind() == 't' {
			c.Secret = nil
			c.SecretUS = sql.NullInt64{Int64: nowUS, Valid: true}
		}
	}
	secret, ok, err := stringMember(data, "client_secret")
	if err != nil || !ok || secret == "" {
		return err
	}
	if !validSecret(secret) {
		return errInvalidConfig
	}
	sealed, err := s.Ring.Seal(keyring.GitHubClientSecret, secretAAD, []byte(secret))
	if err != nil {
		return fmt.Errorf("github: seal client secret: %w", err)
	}
	c.Secret = sealed
	c.SecretUS = sql.NullInt64{Int64: nowUS, Valid: true}
	return nil
}

// unrestricted is auto_provision_unrestricted: any GitHub account could
// create an account on a production instance.
func (s *Service) unrestricted(autoProvision bool, orgs []string) bool {
	return autoProvision && len(orgs) == 0 && s.Production
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
