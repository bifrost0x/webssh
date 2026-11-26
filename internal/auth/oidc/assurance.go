package oidc

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"math/big"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/auth"
)

// Bounds of the assurance evidence (oidc_service.py).
const (
	maxAMRValues      = 16
	maxAMRValueRunes  = 128
	maxACRRunes       = 256
	maxAuthTime       = 253_402_300_799 // 9999-12-31T23:59:59Z
	maxConfiguredRune = 256
)

// evidence is the raw acr, amr and auth_time of a verified ID Token.
type evidence struct {
	acr, amr, authTime jsontext.Value
}

// AssurancePolicy is OIDC_MFA_ACR_VALUES, OIDC_MFA_AMR_VALUES,
// OIDC_PHISHING_RESISTANT_ACR_VALUES and OIDC_PHISHING_RESISTANT_AMR_VALUES.
// Only values listed here raise a sign-in above BASIC (C-IDP-04).
type AssurancePolicy struct {
	MFAACR, MFAAMR, PhishingACR, PhishingAMR []string
}

// Assessment is the assurance read from one ID Token.
type Assessment struct {
	Level auth.Assurance
	ACR   string
	AMR   []string
	// AuthTime is zero when the token carries no valid auth_time.
	AuthTime time.Time
	// Reason is the Python reason code: explicit_match,
	// no_configured_match, malformed_evidence, conflicting_evidence,
	// missing_auth_time.
	Reason string
}

// configured is _configured_values: one empty or over-long value voids
// the whole list, so a typo never grants assurance.
func configured(values []string) []string {
	for _, v := range values {
		if v == "" || utf8.RuneCountInString(v) > maxConfiguredRune {
			return nil
		}
	}
	return values
}

// normalize is _normalize_assurance_claims. valid is false for malformed
// evidence; the values read up to the fault are returned for the log.
func (e evidence) normalize() (acr string, amr []string, authTime int64, hasTime, valid bool) {
	if len(e.acr) > 0 && e.acr.Kind() != 'n' {
		s, ok := strictString(e.acr)
		if !ok || s == "" || utf8.RuneCountInString(s) > maxACRRunes {
			return "", nil, 0, false, false
		}
		acr = s
	}
	if len(e.amr) > 0 && e.amr.Kind() != 'n' {
		var raw []jsontext.Value
		if e.amr.Kind() != '[' || json.Unmarshal(e.amr, &raw) != nil || len(raw) > maxAMRValues {
			return acr, nil, 0, false, false
		}
		for _, v := range raw {
			s, ok := strictString(v)
			if !ok || s == "" || utf8.RuneCountInString(s) > maxAMRValueRunes {
				return acr, nil, 0, false, false
			}
			if !slices.Contains(amr, s) {
				amr = append(amr, s)
			}
		}
	}
	if len(e.authTime) > 0 && e.authTime.Kind() != 'n' {
		t, ok := pythonInt(e.authTime)
		if !ok || t <= 0 || t > maxAuthTime {
			return acr, amr, 0, false, false
		}
		authTime, hasTime = t, true
	}
	return acr, amr, authTime, hasTime, true
}

// pythonInt reads a JSON number that Python's json module decodes as an
// int: digits with an optional minus sign, no fraction or exponent.
// Booleans are not numbers in JSON, so the bool exclusion of the Python
// check (type(auth_time) is not int) needs no extra case.
func pythonInt(v jsontext.Value) (int64, bool) {
	if v.Kind() != '0' {
		return 0, false
	}
	text := string(v)
	for i, r := range text {
		if (r < '0' || r > '9') && !(i == 0 && r == '-') {
			return 0, false
		}
	}
	n, ok := new(big.Int).SetString(text, 10)
	if !ok || !n.IsInt64() {
		return 0, false
	}
	return n.Int64(), true
}

func claimLevel(value string, mfa, phishing []string) (auth.Assurance, bool) {
	inMFA, inPhishing := slices.Contains(mfa, value), slices.Contains(phishing, value)
	switch {
	case inMFA && inPhishing:
		return "", true
	case inPhishing:
		return auth.AssurancePhishingResistant, false
	case inMFA:
		return auth.AssuranceMFA, false
	}
	return auth.AssuranceBasic, false
}

// assess is evaluate_oidc_assurance: only bounded, explicitly configured
// ID Token claims raise the assurance, conflicts and a missing auth_time
// fall back to BASIC.
func (pol AssurancePolicy) assess(e evidence) Assessment {
	acr, amr, authTime, hasTime, valid := e.normalize()
	out := Assessment{Level: auth.AssuranceBasic, ACR: acr, AMR: amr}
	if hasTime {
		out.AuthTime = time.Unix(authTime, 0).UTC()
	}
	if !valid {
		out.Reason = "malformed_evidence"
		return out
	}
	mfaACR, mfaAMR := configured(pol.MFAACR), configured(pol.MFAAMR)
	phACR, phAMR := configured(pol.PhishingACR), configured(pol.PhishingAMR)
	// An absent acr matches nothing: configured values are never empty.
	acrLevel, conflict := auth.AssuranceBasic, false
	if acr != "" {
		acrLevel, conflict = claimLevel(acr, mfaACR, phACR)
	}
	amrLevel := auth.AssuranceBasic
	for _, v := range amr {
		level, c := claimLevel(v, mfaAMR, phAMR)
		conflict = conflict || c
		if !c && level.Rank() > amrLevel.Rank() {
			amrLevel = level
		}
	}
	if conflict || (acrLevel != auth.AssuranceBasic && amrLevel != auth.AssuranceBasic && acrLevel != amrLevel) {
		out.Reason = "conflicting_evidence"
		return out
	}
	level := acrLevel
	if amrLevel.Rank() > level.Rank() {
		level = amrLevel
	}
	if level != auth.AssuranceBasic && !hasTime {
		out.AuthTime = time.Time{}
		out.Reason = "missing_auth_time"
		return out
	}
	out.Level = level
	out.Reason = "no_configured_match"
	if level != auth.AssuranceBasic {
		out.Reason = "explicit_match"
	}
	return out
}
