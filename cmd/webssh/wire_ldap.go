package main

import (
	"github.com/bifrost0x/webssh/internal/auth/ldap"
	"github.com/bifrost0x/webssh/internal/auth/stepup"
	"github.com/bifrost0x/webssh/internal/session"
)

// ldapArea wires the area "ldap" (ID1): LDAP and Active Directory sign-in (internal/auth/ldap, internal/ldapproto).
// ID1 fills in the hooks; no other package edits this file.
func ldapArea() extension {
	return extension{name: "ldap"}
}

// The providers that exist already satisfy the consumer interfaces of
// the area.
var (
	_ ldap.Sessions = (*session.Service)(nil)
	_ ldap.StepUp   = (*stepup.Service)(nil)
)
