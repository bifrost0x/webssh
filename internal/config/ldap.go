package config

import (
	"regexp"
	"strings"
)

var (
	ldapProviderID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	ldapAttribute  = regexp.MustCompile(`^(?:[A-Za-z][A-Za-z0-9-]*|[0-9]+(?:\.[0-9]+)+)$`)
)

// validateLDAP is the LDAP part of validate_security_config. LDAP sign-in
// is not part of this preview, but a configuration the Python release
// refuses is refused here as well.
func validateLDAP(l *ldapSettings) error {
	for _, s := range []struct{ name, value string }{
		{"LDAP_URL", l.url}, {"LDAP_PROVIDER_ID", l.providerID}, {"LDAP_BASE_DN", l.baseDN},
		{"LDAP_BIND_DN", l.bindDN}, {"LDAP_BIND_PASSWORD_FILE", l.bindPasswordFile},
		{"LDAP_CA_FILE", l.caFile}, {"LDAP_USER_FILTER", l.userFilter},
		{"LDAP_UNIQUE_ID_ATTRIBUTE", l.uniqueID},
	} {
		if s.value == "" {
			return configError(s.name, "SECURITY ERROR: "+s.name+" is required when LDAP_ENABLED is true")
		}
	}
	primary, err := ldapURL("LDAP_URL", l.url)
	if err != nil {
		return err
	}
	if l.backupURL != "" {
		backup, err := ldapURL("LDAP_BACKUP_URL", l.backupURL)
		if err != nil {
			return err
		}
		if backup == primary {
			return configError("LDAP_BACKUP_URL", "SECURITY ERROR: LDAP_BACKUP_URL must identify a different server than LDAP_URL")
		}
	}
	if strings.Count(l.userFilter, "{username}") != 1 {
		return configError("LDAP_USER_FILTER", "SECURITY ERROR: LDAP_USER_FILTER must contain exactly one {username} placeholder")
	}
	rest := strings.ReplaceAll(l.userFilter, "{username}", "")
	if runeLen(l.userFilter) > 4096 || strings.Contains(l.userFilter, "\x00") || strings.ContainsAny(rest, "{}") {
		return configError("LDAP_USER_FILTER", "SECURITY ERROR: LDAP_USER_FILTER contains an unsupported template or exceeds the size limit")
	}
	if !ldapProviderID.MatchString(l.providerID) {
		return configError("LDAP_PROVIDER_ID", "SECURITY ERROR: LDAP_PROVIDER_ID must be a short, stable identifier containing only letters, digits, dot, dash, or underscore")
	}
	if !ldapAttribute.MatchString(l.uniqueID) {
		return configError("LDAP_UNIQUE_ID_ATTRIBUTE", "SECURITY ERROR: LDAP_UNIQUE_ID_ATTRIBUTE must be an LDAP attribute name or numeric OID")
	}
	for _, dn := range []struct{ name, value string }{{"LDAP_BASE_DN", l.baseDN}, {"LDAP_BIND_DN", l.bindDN}} {
		if runeLen(dn.value) > 2048 || strings.Contains(dn.value, "\x00") {
			return configError(dn.name, "SECURITY ERROR: "+dn.name+" is invalid or exceeds the size limit")
		}
	}
	if !strings.HasPrefix(l.bindPasswordFile, "/") {
		return configError("LDAP_BIND_PASSWORD_FILE", "SECURITY ERROR: LDAP_BIND_PASSWORD_FILE must be an absolute path")
	}
	if !strings.HasPrefix(l.caFile, "/") {
		return configError("LDAP_CA_FILE", "SECURITY ERROR: LDAP_CA_FILE must be an absolute path")
	}
	if pyPath(l.bindPasswordFile) == pyPath(l.caFile) {
		return configError("LDAP_CA_FILE", "SECURITY ERROR: LDAP_BIND_PASSWORD_FILE and LDAP_CA_FILE must be different files")
	}
	return nil
}

type ldapEndpoint struct {
	scheme, host string
	port         int
}

// ldapURL is _validate_ldap_url; it returns _ldap_endpoint_identity. The
// identity folds case with lower() where Python uses casefold(); the two
// differ only for a few non-ASCII letters.
func ldapURL(name, value string) (ldapEndpoint, error) {
	bad := configError(name, "SECURITY ERROR: "+name+" must be an exact ldap:// or ldaps:// server URL without credentials, path, query, or fragment and with a valid port")
	u, err := pyURLSplit(value)
	if err != nil {
		return ldapEndpoint{}, bad
	}
	host := u.hostname()
	port, err := u.port()
	if err != nil || u.scheme != "ldap" && u.scheme != "ldaps" || host == "" || port == 0 ||
		u.hasCredentials() || u.path != "" || u.query != "" || u.fragment != "" {
		return ldapEndpoint{}, bad
	}
	if port < 0 {
		port = 389
		if u.scheme == "ldaps" {
			port = 636
		}
	}
	return ldapEndpoint{scheme: u.scheme, host: strings.TrimRight(pyLower(host), "."), port: port}, nil
}
