package main

import (
	// Fallback roots apply only when the platform has neither a certificate
	// verifier nor a bundle, for example a scratch image whose
	// /etc/ssl/certs was not mounted or a host without CA certificates. The
	// image ships the bundle; this keeps TLS to public servers working
	// without it.
	_ "golang.org/x/crypto/x509roots/fallback"
	// The image has no /usr/share/zoneinfo; TZ resolves against the zone
	// database built into the binary.
	_ "time/tzdata"
)
