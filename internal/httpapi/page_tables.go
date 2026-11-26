package httpapi

// flashMessageKeys translates the known application messages; other
// messages, such as provider details, are shown as they are. The table
// matches templates/_auth_messages.html.
var flashMessageKeys = map[string]string{ // #nosec G101 -- message texts and translation keys, no credentials
	"Please log in to access this page.":                      "auth.loginRequired",
	"Invalid username or password":                            "auth.invalidCredentials",
	"Too many login attempts. Please try again later.":        "auth.tooManyAttempts",
	"Too many registration attempts. Please try again later.": "auth.tooManyAttempts",
	"Too many attempts. Please try again later.":              "auth.tooManyAttempts",
	"Too many invalid codes. Sign in again.":                  "auth.mfaRestart",
	"You were signed out in this browser, but the server could not end your session. Change your password or ask an administrator to end your sessions.": "auth.partialLogout",
	"Registration is currently disabled.":                         "auth.registrationDisabled",
	"This account is locked. Please contact an administrator.":    "auth.accountLocked",
	"Account created successfully!":                               "auth.accountCreated",
	"Passwords do not match":                                      "auth.passwordsNoMatch",
	"New passwords do not match":                                  "auth.passwordsNoMatch",
	"Current password is incorrect":                               "auth.currentPasswordIncorrect",
	"New password must be different from current password":        "auth.passwordMustDiffer",
	"Password updated successfully":                               "auth.passwordUpdated",
	"Username must be between 3 and 32 characters":                "auth.newUsernameLength",
	"Username can only contain letters, numbers, and underscores": "auth.newUsernameCharacters",
	"Username already exists":                                     "auth.newUsernameTaken",
	"Password must be at least 8 characters":                      "auth.newPasswordTooShort",
	"New password must be at least 8 characters":                  "auth.newPasswordChangeTooShort",
}

// flashDataCategories carry form data for the sign-in page and are never
// shown as messages.
var flashDataCategories = []string{"login_username", "login_auth_source"}

// authMethodKeys are the translation keys of the sign-in methods the
// settings page names.
var authMethodKeys = []string{
	"security.methodLdap",
	"security.methodOidc",
	"security.methodGithub",
	"security.methodPasskey",
	"security.methodPassword",
	"security.methodTotp",
	"security.methodRecoveryCode",
}

// hostPlatforms have an icon in static/icons/platforms/.
var hostPlatforms = []string{
	"almalinux", "alpinelinux", "apple", "archlinux", "centos", "cisco",
	"debian", "docker", "endeavouros", "fedora", "freebsd", "homeassistant",
	"kalilinux", "linux", "linuxmint", "manjaro", "mikrotik", "nixos",
	"opensuse", "openwrt", "opnsense", "pfsense", "popos", "proxmox", "qnap",
	"raspberrypi", "redhat", "synology", "truenas", "ubiquiti", "ubuntu",
	"unraid", "voidlinux",
}
