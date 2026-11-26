package config

// OIDC holds the OIDC_* variables (config.py). The values are read
// whether or not Enabled is set; the start-up checks of issuer and
// redirect run only when it is.
type OIDC struct {
	Enabled bool
	// Issuer is OIDC_ISSUER without trailing slashes.
	Issuer           string
	ClientID         string
	ClientSecretFile string
	RedirectURI      string
	// AllowedSubjects and AllowedDomains (lower case) are
	// OIDC_ALLOWED_SUBJECTS and OIDC_ALLOWED_DOMAINS.
	AllowedSubjects []string
	AllowedDomains  []string
	// LoginRateLimit is OIDC_LOGIN_RATE_LIMIT, a rate limit string.
	LoginRateLimit string
	// The assurance mapping (OIDC_MFA_*, OIDC_PHISHING_RESISTANT_*) and
	// OIDC_STEP_UP_ACR_VALUES.
	MFAACR, MFAAMR, PhishingACR, PhishingAMR, StepUpACR []string
}
