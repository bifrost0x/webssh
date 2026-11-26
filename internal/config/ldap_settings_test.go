package config

import (
	"testing"
	"time"
)

func TestLDAPSettingsArePublished(t *testing.T) {
	c, _ := mustLoad(t, map[string]string{
		"LDAP_ENABLED": "true", "LDAP_AUTO_PROVISION": "true", "LDAP_URL": "ldap://dir.example.test",
		"LDAP_BACKUP_URL": "ldaps://dir2.example.test", "LDAP_BASE_DN": "dc=example", "LDAP_BIND_DN": "cn=svc,dc=example",
		"LDAP_USER_FILTER": "(uid={username})", "LDAP_UNIQUE_ID_ATTRIBUTE": "entryUUID", "LDAP_PROVIDER_ID": "corp",
		"LDAP_CONNECT_TIMEOUT": "3", "LDAP_OPERATION_TIMEOUT": "7", "LDAP_SESSION_REVALIDATION_SECONDS": "120",
		"LDAP_LOGIN_RATE_LIMIT": "3 per minute",
	})
	want := LDAP{Enabled: true, AutoProvision: true, ProviderID: "corp", URL: "ldap://dir.example.test",
		BackupURL: "ldaps://dir2.example.test", BaseDN: "dc=example", BindDN: "cn=svc,dc=example",
		BindPasswordFile: "/run/webssh-auth/ldap_bind_password", CAFile: "/run/webssh-auth/ldap_ca.pem",
		UserFilter: "(uid={username})", UniqueIDAttribute: "entryUUID", LoginRateLimit: "3 per minute",
		ConnectTimeout: 3 * time.Second, OperationTimeout: 7 * time.Second, Revalidation: 2 * time.Minute}
	if c.LDAP != want {
		t.Fatalf("got %+v\nwant %+v", c.LDAP, want)
	}
	c, _ = mustLoad(t, map[string]string{})
	if c.LDAP.Enabled || c.LDAP.Revalidation != 300*time.Second || c.LDAP.ProviderID != "default" {
		t.Fatalf("defaults %+v", c.LDAP)
	}
}
