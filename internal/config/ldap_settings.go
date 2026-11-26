package config

import "time"

// LDAP holds the LDAP and Active Directory settings (LDAP_*). Load has
// checked them like validate_security_config when Enabled is set; the
// directory files are read only when they are used.
type LDAP struct {
	Enabled       bool
	AutoProvision bool
	ProviderID    string
	URL           string
	BackupURL     string
	BaseDN        string
	BindDN        string
	// BindPasswordFile and CAFile are LDAP_BIND_PASSWORD_FILE and
	// LDAP_CA_FILE; only the CA bundle is trusted for the directory.
	BindPasswordFile  string
	CAFile            string
	UserFilter        string
	UniqueIDAttribute string
	// LoginRateLimit is LDAP_LOGIN_RATE_LIMIT in the Flask-Limiter
	// notation; its consumer parses it.
	LoginRateLimit string
	// ConnectTimeout covers connect, TLS and bind; OperationTimeout the
	// search (LDAP_CONNECT_TIMEOUT, LDAP_OPERATION_TIMEOUT).
	ConnectTimeout   time.Duration
	OperationTimeout time.Duration
	// Revalidation is LDAP_SESSION_REVALIDATION_SECONDS.
	Revalidation time.Duration
}

func (in *ldapSettings) public(enabled, autoProvision bool, rateLimit string, connect, operation, revalidation int64) LDAP {
	return LDAP{
		Enabled: enabled, AutoProvision: autoProvision, ProviderID: in.providerID, URL: in.url, BackupURL: in.backupURL,
		BaseDN: in.baseDN, BindDN: in.bindDN, BindPasswordFile: in.bindPasswordFile, CAFile: in.caFile,
		UserFilter: in.userFilter, UniqueIDAttribute: in.uniqueID, LoginRateLimit: rateLimit,
		ConnectTimeout: seconds(connect), OperationTimeout: seconds(operation), Revalidation: seconds(revalidation),
	}
}
