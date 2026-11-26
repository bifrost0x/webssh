// Package audit writes the security audit log.
//
// The log is DATA_DIR/logs/security_audit.log with the line format of the
// Python release (invariant I-10): one JSON object per line with the
// members timestamp, level, logger and message, encoded like Python's
// json.dumps (", " and ": " separators, non-ASCII as \u escapes). The
// message is "EVENT | key=value | …" with the same sanitising, redaction
// and key order, so old and new lines read and export alike. Rotation
// follows logging.handlers.RotatingFileHandler: before a line would reach
// AUDIT_LOG_MAX_BYTES the file moves to .1, older files shift up to the
// backup count and the rest is removed.
//
// M1 builds the writer only; reading, export and retention follow in B7.
package audit
