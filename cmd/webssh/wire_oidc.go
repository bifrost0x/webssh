package main

import (
	"github.com/bifrost0x/webssh/internal/auth/oidc"
	"github.com/bifrost0x/webssh/internal/auth/stepup"
)

// oidcArea wires the area "oidc" (ID2): OpenID Connect sign-in (internal/auth/oidc).
// ID2 fills in the hooks; no other package edits this file.
func oidcArea() extension {
	return extension{name: "oidc"}
}

// The providers that exist already satisfy the consumer interfaces of
// the area.
var (
	_ oidc.StepUp = (*stepup.Service)(nil)
)
