// Package settings owns the application settings, the per-account
// settings (theme, start page, overview layout and panels, terminal
// appearance, session preferences, the introduction tour) and the
// settings the upgrade derives from the behaviour of the Python release
// (D-01).
//
// Application settings keep every key of the legacy app_settings.json,
// also those this release does not act on, so that nothing an
// administrator chose is lost. Account settings keep unknown keys as well:
// a value a newer release wrote survives a rollback and every save.
//
// The package validates values exactly like the Python release where the
// browser contract depends on it (app/user_settings.py,
// app/terminal_appearance.py, app/app_settings.py). Stored values are JSON
// texts; numbers keep their original digits, so integers above 2^53 are
// never rounded.
package settings
