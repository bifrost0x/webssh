package main

import (
	"github.com/bifrost0x/webssh/internal/auth/github"
	"github.com/bifrost0x/webssh/internal/auth/stepup"
)

// githubArea wires the area "github" (ID3): GitHub sign-in and the factor bootstrap (internal/auth/github).
// ID3 fills in the hooks; no other package edits this file.
func githubArea() extension {
	return extension{name: "github"}
}

// The providers that exist already satisfy the consumer interfaces of
// the area.
var (
	_ github.StepUp = (*stepup.Service)(nil)
)
