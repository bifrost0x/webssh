package e2eseed

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
)

// Version is the seed format version this applier understands.
const Version = 1

// maxSeedSize bounds the seed file; the checked-in seed is a few KiB.
const maxSeedSize = 1 << 20

// Seed is tests/e2e/seed.json, format version 1. tests/e2e/README.md
// describes the meaning of every member; tests/e2e/run_app.py is the
// reference implementation.
type Seed struct {
	Version            int               `json:"version"`
	Environment        map[string]string `json:"environment"`
	UnsetEnvironment   []string          `json:"unset_environment"`
	DataFiles          map[string]string `json:"data_files"`
	AdminSettings      AdminSettings     `json:"admin_settings"`
	Accounts           []Account         `json:"accounts"`
	AccountSettings    *AccountSettings  `json:"account_settings"`
	ExternalIdentities []OwnedEntry      `json:"external_identities"`
	SecurityFeatures   []SecurityFeature `json:"security_features"`
	MFAPlaceholders    []MFAPlaceholder  `json:"mfa_placeholders"`
	SSHKeys            []SSHKey          `json:"ssh_keys"`
	JumpHosts          []JumpHost        `json:"jump_hosts"`
	SOCKSProxies       []SOCKSProxy      `json:"socks_proxies"`
	Commands           []OwnedEntry      `json:"commands"`
	CommandSets        []OwnedEntry      `json:"command_sets"`
	Profiles           []Profile         `json:"profiles"`
	TestHooks          []Hook            `json:"test_hooks"`

	// peer is the running automation peer of the hook (Run starts it).
	peer *AutomationPeer
}

// AdminSettings are the admin policies applied before accounts exist.
type AdminSettings struct {
	AutomationEnabled        *bool `json:"automation_enabled"`
	RegistrationEnabled      *bool `json:"registration_enabled"`
	LoginUsernameLimit       *int  `json:"login_username_limit"`
	LoginUsernameGlobalLimit *int  `json:"login_username_global_limit"`
}

// Account is a local account. Ref is how other entries name it.
type Account struct {
	Ref        string `json:"ref"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	Admin      bool   `json:"admin"`
	MFAEnabled bool   `json:"mfa_enabled"`
}

// AccountSettings are stored for every seeded account.
type AccountSettings struct {
	IntroTour               string `json:"intro_tour"`
	IntroTourV3Acknowledged bool   `json:"intro_tour_v3_acknowledged"`
}

// OwnedEntry is an entry of a section this build does not apply. Only the
// owning account is interpreted, so that a dangling reference still fails
// the start; the other members are kept as they are.
type OwnedEntry struct {
	Account string
	Members map[string]jsontext.Value
	// Raw is the entry as written, for appliers that keep the member
	// order.
	Raw jsontext.Value
}

// UnmarshalJSON keeps all members and requires a string "account".
func (e *OwnedEntry) UnmarshalJSON(data []byte) error {
	var members map[string]jsontext.Value
	if err := json.Unmarshal(data, &members); err != nil {
		return err
	}
	raw, ok := members["account"]
	if !ok {
		return errors.New("member account is required")
	}
	var account string
	if err := json.Unmarshal(raw, &account); err != nil {
		return fmt.Errorf("member account: %w", err)
	}
	*e = OwnedEntry{Account: account, Members: members, Raw: append(jsontext.Value(nil), data...)}
	return nil
}

// SecurityFeature enables or disables a security feature gate.
type SecurityFeature struct {
	Feature   string `json:"feature"`
	Enabled   bool   `json:"enabled"`
	UpdatedBy string `json:"updated_by"`
}

// MFAPlaceholder marks an account as enrolled in a second factor. It
// cannot be used to authenticate.
type MFAPlaceholder struct {
	Type         string   `json:"type"`
	Account      string   `json:"account"`
	Label        string   `json:"label"`
	Active       *bool    `json:"active"`
	Secret       string   `json:"secret"`
	Name         string   `json:"name"`
	CredentialID string   `json:"credential_id"`
	PublicKey    string   `json:"public_key"`
	Transports   []string `json:"transports"`
}

// SSHKey is a key generated fresh for every run.
type SSHKey struct {
	Ref      string `json:"ref"`
	Account  string `json:"account"`
	Name     string `json:"name"`
	Generate string `json:"generate"`
}

// JumpHost is a saved jump host without a stored password.
type JumpHost struct {
	Ref      string `json:"ref"`
	Account  string `json:"account"`
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	AuthType string `json:"auth_type"`
	Key      string `json:"key"`
	KeyID    string `json:"key_id"`
}

// SOCKSProxy is a saved SOCKS5 proxy without a stored password.
type SOCKSProxy struct {
	Ref       string `json:"ref"`
	Account   string `json:"account"`
	Name      string `json:"name"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	AuthType  string `json:"auth_type"`
	Username  string `json:"username"`
	RemoteDNS bool   `json:"remote_dns"`
}

// Profile is a saved host. Key, JumpHost and SOCKSProxy name the ref of a
// seeded entry; the *ID members are literal ids, possibly dangling on
// purpose.
type Profile struct {
	Account            string  `json:"account"`
	ID                 string  `json:"id"`
	Name               string  `json:"name"`
	Host               string  `json:"host"`
	Port               int     `json:"port"`
	Username           string  `json:"username"`
	AuthType           string  `json:"auth_type"`
	Group              string  `json:"group"`
	SortOrder          *int    `json:"sort_order"`
	Favorite           bool    `json:"favorite"`
	Key                string  `json:"key"`
	KeyID              string  `json:"key_id"`
	JumpHost           string  `json:"jump_host"`
	JumpHostID         string  `json:"jump_host_id"`
	SOCKSProxy         string  `json:"socks_proxy"`
	SOCKSProxyID       string  `json:"socks_proxy_id"`
	StartupMode        string  `json:"startup_mode"`
	StartupCommands    string  `json:"startup_commands"`
	CommandID          string  `json:"command_id"`
	CommandSetID       string  `json:"command_set_id"`
	ParametersOverride *string `json:"parameters_override"`
}

// Hook enables test-only behaviour. Accounts is used by
// automation_ssh_peer, Error by outbound_ssh_guard.
type Hook struct {
	Name     string   `json:"name"`
	Accounts []string `json:"accounts"`
	Error    string   `json:"error"`
}

// Load reads and validates the seed file at path.
func Load(path string) (*Seed, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator names the seed (WEBSSH_E2E_SEED)
	if err != nil {
		return nil, fmt.Errorf("e2e seed: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxSeedSize+1))
	if err != nil {
		return nil, fmt.Errorf("e2e seed %s: %w", path, err)
	}
	if len(data) > maxSeedSize {
		return nil, fmt.Errorf("e2e seed %s: larger than %d bytes", path, maxSeedSize)
	}
	s, err := Decode(data)
	if err != nil {
		return nil, fmt.Errorf("e2e seed %s: %w", path, err)
	}
	return s, nil
}

// Decode parses and validates a seed. Unknown or duplicate members, a
// version other than Version and every inconsistency Validate finds are
// errors: a seed that cannot be applied in full must not start a backend.
func Decode(data []byte) (*Seed, error) {
	var probe struct {
		Version *int `json:"version"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("not a seed object: %w", err)
	}
	if probe.Version == nil || *probe.Version != Version {
		return nil, errors.New("unsupported seed version")
	}
	var s Seed
	if err := json.Unmarshal(data, &s, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("invalid seed: %w", err)
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}
