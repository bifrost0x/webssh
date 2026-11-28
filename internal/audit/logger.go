package audit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// FileName is the audit log in DATA_DIR/logs (invariant I-10).
const FileName = "security_audit.log"

// loggerName is the "logger" member of every line.
const loggerName = "security_audit"

// Level is the Python logging level name written in each line.
type Level string

// Levels used by the audit log.
const (
	Info    Level = "INFO"
	Warning Level = "WARNING"
	Error   Level = "ERROR"
)

// MaxBackupCount is the largest backup count the administrator setting
// accepts (AUDIT_BACKUP_COUNT_MAX).
const MaxBackupCount = 90

// Options configures a Logger.
type Options struct {
	// MaxBytes is AUDIT_LOG_MAX_BYTES; 0 turns rotation off.
	MaxBytes int64
	// BackupCount is the number of rotated files kept (1–90).
	BackupCount int
	// Console receives a copy of every line, as the Python release writes
	// its audit lines to standard output too. Nil writes no copy.
	Console io.Writer
	// Now replaces the clock in tests.
	Now func() time.Time
}

// Logger appends audit lines. It is safe for concurrent use. A failed
// write is reported to the caller of Close and on the console copy, but
// never stops the action that is being audited, as in the Python release.
type Logger struct {
	mu      sync.Mutex
	path    string
	file    *os.File
	size    int64
	opts    Options
	lastErr error
}

// Open opens or creates logsDir/security_audit.log for appending and
// removes rotated files beyond the backup count, like the Python start.
func Open(logsDir string, o Options) (*Logger, error) {
	if o.BackupCount < 1 || o.BackupCount > MaxBackupCount {
		return nil, fmt.Errorf("audit: backup count %d outside 1–%d", o.BackupCount, MaxBackupCount)
	}
	if o.MaxBytes < 0 {
		return nil, errors.New("audit: negative maximum size")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if err := os.MkdirAll(logsDir, 0o700); err != nil {
		return nil, fmt.Errorf("audit: create log directory: %w", err)
	}
	l := &Logger{path: filepath.Join(logsDir, FileName), opts: o}
	if err := l.prune(); err != nil {
		return nil, err
	}
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Logger) open() error {
	// A link or another file type in place of the log is refused, not
	// followed; O_NONBLOCK keeps a FIFO from blocking the open.
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return fmt.Errorf("audit: open log: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("audit: stat log: %w", err)
	}
	if !st.Mode().IsRegular() {
		_ = f.Close()
		return fmt.Errorf("audit: %s is not a regular file", l.path)
	}
	l.file, l.size = f, st.Size()
	return nil
}

// prune is _prune_excess_backups: it removes "<name>.<digits>" files
// numbered above the backup count and nothing else.
func (l *Logger) prune() error {
	dir, base := filepath.Dir(l.path), filepath.Base(l.path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("audit: list log directory: %w", err)
	}
	for _, e := range entries {
		suffix, ok := strings.CutPrefix(e.Name(), base+".")
		if !ok || suffix == "" || strings.Trim(suffix, "0123456789") != "" {
			continue
		}
		if n, err := strconv.Atoi(suffix); err == nil && n <= l.opts.BackupCount {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("audit: prune rotated log: %w", err)
		}
	}
	return nil
}

// SetBackupCount applies the administrator setting audit_backup_count and
// prunes files beyond it (apply_audit_backup_count).
func (l *Logger) SetBackupCount(n int) error {
	if n < 1 || n > MaxBackupCount {
		return fault.New(fault.InvalidValue, "Audit backup count must be between 1 and 90")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.opts.BackupCount = n
	return l.prune()
}

// Event writes a structured security event (log_security_event).
func (l *Logger) Event(level Level, event string, fields ...Field) {
	l.write(level, eventMessage(event, fields))
}

// LoginAttempt is log_login_attempt.
func (l *Logger) LoginAttempt(username string, ok bool, ip, userAgent string) {
	l.write(Info, "LOGIN_"+status(ok)+" | user="+sanitize(username)+" | ip="+sanitize(ip)+" | user_agent="+sanitize(userAgent))
}

// Logout is log_logout.
func (l *Logger) Logout(username, ip string) {
	l.write(Info, "LOGOUT | user="+sanitize(username)+" | ip="+sanitize(ip))
}

// Registration is log_registration.
func (l *Logger) Registration(username string, ok bool, ip string) {
	l.write(Info, "REGISTRATION_"+status(ok)+" | user="+sanitize(username)+" | ip="+sanitize(ip))
}

// PasswordChange is log_password_change.
func (l *Logger) PasswordChange(username string, ok bool, ip string) {
	l.write(Info, "PASSWORD_CHANGE_"+status(ok)+" | user="+sanitize(username)+" | ip="+sanitize(ip))
}

// RateLimitExceeded is log_rate_limit_exceeded; user may be empty.
func (l *Logger) RateLimitExceeded(endpoint, ip, user string) {
	msg := "RATE_LIMIT_EXCEEDED | endpoint=" + sanitize(endpoint) + " | ip=" + sanitize(ip)
	if user != "" {
		msg += " | user=" + sanitize(user)
	}
	l.write(Warning, msg)
}

// RealtimeCall records the outcome of a mutating realtime request
// (realtime.Auditor). It has no Python counterpart: Socket.IO handlers
// logged per feature. The result is the stable error code or "ok"; error
// text never reaches the log.
func (l *Logger) RealtimeCall(_ context.Context, p principal.Principal, msgType string, err error) {
	result, level := "ok", Info
	if err != nil {
		result, level = string(fault.CodeOf(err)), Warning
		if result == "" {
			result = string(fault.Internal)
		}
	}
	l.Event(level, "REALTIME_CALL", F("user", p.Username), F("user_id", p.UserID), F("type", msgType), F("result", result))
}

func status(ok bool) string {
	if ok {
		return "SUCCESS"
	}
	return "FAILED"
}

// timestamp is Python's datetime.now(timezone.utc).isoformat() with
// "+00:00" replaced by "Z": microseconds only when they are not zero.
func timestamp(t time.Time) string {
	t = t.UTC()
	if t.Nanosecond()/1000 == 0 {
		return t.Format("2006-01-02T15:04:05Z")
	}
	return t.Format("2006-01-02T15:04:05.000000Z")
}

func (l *Logger) line(level Level, message string) string {
	var b strings.Builder
	b.WriteString(`{"timestamp": `)
	pyString(&b, timestamp(l.opts.Now()))
	b.WriteString(`, "level": `)
	pyString(&b, string(level))
	b.WriteString(`, "logger": "` + loggerName + `", "message": `)
	pyString(&b, message)
	b.WriteString("}\n")
	return b.String()
}

func (l *Logger) write(level Level, message string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	text := l.line(level, message)
	if l.opts.Console != nil {
		_, _ = io.WriteString(l.opts.Console, text)
	}
	if l.file == nil {
		return
	}
	if err := l.rolloverIfNeeded(int64(len(text))); err != nil {
		l.fail(err)
		if l.file == nil {
			return
		}
	}
	n, err := io.WriteString(l.file, text)
	l.size += int64(n)
	if err != nil {
		l.fail(fmt.Errorf("audit: write: %w", err))
	}
}

func (l *Logger) fail(err error) {
	l.lastErr = err
	if l.opts.Console != nil {
		_, _ = io.WriteString(l.opts.Console, l.line(Error, "AUDIT_LOG_WRITE_FAILED"))
	}
}

// rolloverIfNeeded is RotatingFileHandler.shouldRollover/doRollover: an
// empty file is never rotated; otherwise the file rotates when the new
// line would reach MaxBytes.
func (l *Logger) rolloverIfNeeded(n int64) error {
	if l.opts.MaxBytes <= 0 || l.size == 0 || l.size+n < l.opts.MaxBytes {
		return nil
	}
	if err := l.file.Close(); err != nil {
		l.file = nil
		return fmt.Errorf("audit: close for rotation: %w", err)
	}
	l.file = nil
	for i := l.opts.BackupCount - 1; i >= 1; i-- {
		src := l.path + "." + strconv.Itoa(i)
		if _, err := os.Stat(src); err == nil {
			if err := os.Rename(src, l.path+"."+strconv.Itoa(i+1)); err != nil {
				return errors.Join(fmt.Errorf("audit: rotate: %w", err), l.open())
			}
		}
	}
	if err := os.Rename(l.path, l.path+".1"); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return errors.Join(fmt.Errorf("audit: rotate: %w", err), l.open())
	}
	return l.open()
}

// Close closes the file and reports the last write failure, if any.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	var err error
	if l.file != nil {
		err = l.file.Close()
		l.file = nil
	}
	return errors.Join(l.lastErr, err)
}

// Security writes an INFO security event from alternating keys and
// values. Its signature uses only standard types, so capabilities declare
// it in their own interfaces without importing this package.
func (l *Logger) Security(event string, kv ...any) { l.Event(Info, event, pairs(kv)...) }

// SecurityWarning is Security at level WARNING.
func (l *Logger) SecurityWarning(event string, kv ...any) { l.Event(Warning, event, pairs(kv)...) }

func pairs(kv []any) []Field {
	fields := make([]Field, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		key, ok := kv[i].(string)
		if !ok {
			key = "[INVALID_KEY]"
		}
		fields = append(fields, F(key, kv[i+1]))
	}
	return fields
}
