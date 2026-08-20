import logging
import json
import sys
from collections.abc import Mapping
from threading import RLock
from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import datetime, timezone
import config

LOGS_DIR = config.DATA_DIR / 'logs'
_file_logging_lock = RLock()

class StructuredFormatter(logging.Formatter):
    """JSON structured logging formatter for production."""

    def format(self, record):
        log_data = {
            'timestamp': datetime.now(timezone.utc).isoformat().replace(
                '+00:00', 'Z'
            ),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }

        if hasattr(record, 'extra_data'):
            log_data.update(record.extra_data)

        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)

        return json.dumps(log_data)

class ConsoleFormatter(logging.Formatter):
    """Human-readable formatter for console output."""

    COLORS = {
        'DEBUG': '\033[36m',
        'INFO': '\033[32m',
        'WARNING': '\033[33m',
        'ERROR': '\033[31m',
        'CRITICAL': '\033[35m',
    }
    RESET = '\033[0m'
    ICONS = {
        'DEBUG': '🔍',
        'INFO': '✓',
        'WARNING': '⚠️',
        'ERROR': '❌',
        'CRITICAL': '🚨',
    }

    def format(self, record):
        color = self.COLORS.get(record.levelname, '')
        icon = self.ICONS.get(record.levelname, '')
        reset = self.RESET if color else ''

        timestamp = datetime.now().strftime('%H:%M:%S')

        msg = f"{color}{icon} [{timestamp}] {record.getMessage()}{reset}"

        if record.exc_info:
            msg += f"\n{self.formatException(record.exc_info)}"

        return msg


def _prune_excess_backups(log_file, backup_count):
    log_path = Path(log_file)
    prefix = f'{log_path.name}.'
    failures = []
    for candidate in log_path.parent.glob(f'{log_path.name}.*'):
        suffix = candidate.name[len(prefix):]
        if not suffix.isdigit():
            continue
        if int(suffix) <= backup_count:
            continue
        try:
            candidate.unlink()
        except FileNotFoundError:
            continue
        except OSError as error:
            failures.append((candidate, type(error).__name__))
    return failures


def setup_logger(name, log_file=None, level=logging.INFO):
    """Setup a logger with console and optional file output."""
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if logger.handlers:
        return logger

    if log_file:
        _prune_excess_backups(
            log_file,
            config.AUDIT_LOG_BACKUP_COUNT,
        )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)

    if config.DEBUG:
        console_handler.setFormatter(ConsoleFormatter())
    else:
        console_handler.setFormatter(StructuredFormatter())

    logger.addHandler(console_handler)

    if log_file:
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=config.AUDIT_LOG_MAX_BYTES,
            backupCount=config.AUDIT_LOG_BACKUP_COUNT,
            encoding='utf-8',
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(StructuredFormatter())
        logger.addHandler(file_handler)

    return logger

app_logger = setup_logger(
    'webssh',
    level=logging.DEBUG if config.DEBUG else logging.INFO
)

audit_logger = setup_logger(
    'security_audit',
    level=logging.INFO
)


def initialize_file_logging(data_dir=None):
    """Attach persistent handlers only after storage initialization is allowed."""
    logs_dir = Path(data_dir or config.DATA_DIR) / 'logs'
    with _file_logging_lock:
        logs_dir.mkdir(parents=True, exist_ok=True)
        for logger, filename in (
            (app_logger, 'app.log'),
            (audit_logger, 'security_audit.log'),
        ):
            target = logs_dir / filename
            target_resolved = target.resolve()
            for handler in tuple(logger.handlers):
                if (
                    isinstance(handler, RotatingFileHandler)
                    and Path(handler.baseFilename) != target_resolved
                ):
                    logger.removeHandler(handler)
                    handler.close()
            if any(
                isinstance(handler, RotatingFileHandler)
                and Path(handler.baseFilename) == target_resolved
                for handler in logger.handlers
            ):
                continue
            _prune_excess_backups(target, config.AUDIT_LOG_BACKUP_COUNT)
            file_handler = RotatingFileHandler(
                target,
                maxBytes=config.AUDIT_LOG_MAX_BYTES,
                backupCount=config.AUDIT_LOG_BACKUP_COUNT,
                encoding='utf-8',
            )
            file_handler.setLevel(logger.level)
            file_handler.setFormatter(StructuredFormatter())
            logger.addHandler(file_handler)

def apply_audit_backup_count(value=None):
    """Apply the persisted rotation count to active log handlers."""
    if value is None:
        from .app_settings import get_audit_backup_count
        value = get_audit_backup_count()
    if type(value) is not int or not 1 <= value <= 90:
        raise ValueError('Audit backup count must be between 1 and 90')
    deferred_prunes = 0
    with _file_logging_lock:
        for logger in (app_logger, audit_logger):
            for handler in logger.handlers:
                if isinstance(handler, RotatingFileHandler):
                    handler.acquire()
                    try:
                        handler.backupCount = value
                        failures = _prune_excess_backups(
                            handler.baseFilename, value
                        )
                        deferred_prunes += len(failures)
                    finally:
                        handler.release()
    if deferred_prunes:
        log_warning(
            'Audit log archive pruning deferred',
            count=deferred_prunes,
        )
    return value

def log_info(message, **kwargs):
    """Log info message with optional structured data."""
    safe_message = _sanitize_log_value(message)
    if kwargs:
        record = logging.LogRecord(
            'webssh', logging.INFO, '', 0, safe_message, (), None
        )
        record.extra_data = kwargs
        app_logger.handle(record)
    else:
        app_logger.info(safe_message)

def log_warning(message, **kwargs):
    """Log warning message with optional structured data."""
    safe_message = _sanitize_log_value(message)
    if kwargs:
        record = logging.LogRecord(
            'webssh', logging.WARNING, '', 0, safe_message, (), None
        )
        record.extra_data = kwargs
        app_logger.handle(record)
    else:
        app_logger.warning(safe_message)

def log_error(message, exc_info=False, **kwargs):
    """Log error message with optional exception and structured data."""
    safe_message = _sanitize_log_value(message)
    if kwargs:
        record = logging.LogRecord(
            'webssh', logging.ERROR, '', 0, safe_message, (), None
        )
        record.extra_data = kwargs
        if exc_info:
            import sys
            record.exc_info = sys.exc_info()
        app_logger.handle(record)
    else:
        app_logger.error(safe_message, exc_info=exc_info)

def log_debug(message, **kwargs):
    """Log debug message with optional structured data."""
    safe_message = _sanitize_log_value(message)
    if kwargs:
        record = logging.LogRecord(
            'webssh', logging.DEBUG, '', 0, safe_message, (), None
        )
        record.extra_data = kwargs
        app_logger.handle(record)
    else:
        app_logger.debug(safe_message)

def _sanitize_log_value(value):
    """Sanitize a value for safe inclusion in log entries.

    Prevents log injection by removing newlines, carriage returns,
    and null bytes that could forge fake log entries.
    """
    if value is None:
        return 'None'
    s = str(value)
    s = s.replace('\n', '\\n').replace('\r', '\\r').replace('\x00', '\\x00')
    return s[:512]


_SENSITIVE_AUDIT_DETAIL_KEYS = frozenset({
    'assertion',
    'authorization',
    'cookie',
    'credential',
    'password',
    'passphrase',
    'private_key',
    'recovery_code',
    'secret',
    'token',
    'totp_code',
})
_SENSITIVE_AUDIT_DETAIL_SUFFIXES = tuple(
    f'_{key}' for key in _SENSITIVE_AUDIT_DETAIL_KEYS
)
_SENSITIVE_AUDIT_DETAIL_PARTS = frozenset({
    'assertion', 'assertions',
    'authorization',
    'cookie', 'cookies',
    'credential', 'credentials',
    'passphrase', 'passphrases',
    'password', 'passwords',
    'secret', 'secrets',
    'token', 'tokens',
})


def _audit_detail_key_is_sensitive(key):
    normalized = ''.join(
        character.lower() if character.isalnum() else '_'
        for character in str(key)
    ).strip('_')
    return (
        normalized in _SENSITIVE_AUDIT_DETAIL_KEYS
        or normalized.endswith(_SENSITIVE_AUDIT_DETAIL_SUFFIXES)
        or bool(
            set(normalized.split('_')) & _SENSITIVE_AUDIT_DETAIL_PARTS
        )
    )


def _redact_audit_detail(key, value):
    if _audit_detail_key_is_sensitive(key):
        return '[REDACTED]'
    if isinstance(value, Mapping):
        return sanitize_audit_details(value)
    if isinstance(value, list):
        return [_redact_audit_detail('', item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_audit_detail('', item) for item in value)
    return value


def sanitize_audit_details(details):
    """Return structured audit details with secret-bearing fields redacted."""
    return {
        str(key): _redact_audit_detail(key, value)
        for key, value in details.items()
    }

def log_login_attempt(username, success, ip_address, user_agent=None):
    status = "SUCCESS" if success else "FAILED"
    audit_logger.info(
        f"LOGIN_{status} | user={_sanitize_log_value(username)} | "
        f"ip={_sanitize_log_value(ip_address)} | user_agent={_sanitize_log_value(user_agent)}"
    )

def log_logout(username, ip_address):
    audit_logger.info(
        f"LOGOUT | user={_sanitize_log_value(username)} | ip={_sanitize_log_value(ip_address)}"
    )

def log_registration(username, success, ip_address):
    status = "SUCCESS" if success else "FAILED"
    audit_logger.info(
        f"REGISTRATION_{status} | user={_sanitize_log_value(username)} | "
        f"ip={_sanitize_log_value(ip_address)}"
    )

def log_password_change(username, success, ip_address):
    status = "SUCCESS" if success else "FAILED"
    audit_logger.info(
        f"PASSWORD_CHANGE_{status} | user={_sanitize_log_value(username)} | "
        f"ip={_sanitize_log_value(ip_address)}"
    )

def log_ssh_connection(username, target_host, target_port, success, ip_address, error=None):
    status = "SUCCESS" if success else "FAILED"
    error_msg = f" | error={_sanitize_log_value(error)}" if error else ""
    audit_logger.info(
        f"SSH_CONNECT_{status} | user={_sanitize_log_value(username)} | "
        f"target={_sanitize_log_value(target_host)}:{target_port} | "
        f"ip={_sanitize_log_value(ip_address)}{error_msg}"
    )


def log_tailscale_ssh_usage(username, target_host, target_port, remote_username,
                            ip_address, allowed, error=None):
    """Audit use of the WebSSH node's shared Tailscale identity."""
    status = "AUTHORIZED" if allowed else "DENIED"
    error_msg = f" | error={_sanitize_log_value(error)}" if error else ""
    audit_logger.info(
        f"TAILSCALE_SSH_{status} | user={_sanitize_log_value(username)} | "
        f"target={_sanitize_log_value(target_host)}:{target_port} | "
        f"remote_user={_sanitize_log_value(remote_username)} | "
        f"ip={_sanitize_log_value(ip_address)} | identity=shared-node{error_msg}"
    )

def log_ssh_disconnect(username, target_host, target_port, ip_address, reason=None):
    reason_msg = f" | reason={_sanitize_log_value(reason)}" if reason else ""
    audit_logger.info(
        f"SSH_DISCONNECT | user={_sanitize_log_value(username)} | "
        f"target={_sanitize_log_value(target_host)}:{target_port} | "
        f"ip={_sanitize_log_value(ip_address)}{reason_msg}"
    )

def log_file_upload(username, target_host, filename, size, success, ip_address, error=None):
    status = "SUCCESS" if success else "FAILED"
    error_msg = f" | error={_sanitize_log_value(error)}" if error else ""
    audit_logger.info(
        f"FILE_UPLOAD_{status} | user={_sanitize_log_value(username)} | "
        f"target={_sanitize_log_value(target_host)} | "
        f"file={_sanitize_log_value(filename)} | size={size} | "
        f"ip={_sanitize_log_value(ip_address)}{error_msg}"
    )

def log_file_download(username, target_host, filename, size, success, ip_address, error=None):
    status = "SUCCESS" if success else "FAILED"
    error_msg = f" | error={_sanitize_log_value(error)}" if error else ""
    audit_logger.info(
        f"FILE_DOWNLOAD_{status} | user={_sanitize_log_value(username)} | "
        f"target={_sanitize_log_value(target_host)} | "
        f"file={_sanitize_log_value(filename)} | size={size} | "
        f"ip={_sanitize_log_value(ip_address)}{error_msg}"
    )

def log_key_upload(username, key_name, success, ip_address):
    status = "SUCCESS" if success else "FAILED"
    audit_logger.info(
        f"KEY_UPLOAD_{status} | user={_sanitize_log_value(username)} | "
        f"key={_sanitize_log_value(key_name)} | ip={_sanitize_log_value(ip_address)}"
    )


def log_key_rename(username, old_name, new_name, ip_address):
    audit_logger.info(
        f"KEY_RENAME | user={_sanitize_log_value(username)} | "
        f"old={_sanitize_log_value(old_name)} | "
        f"new={_sanitize_log_value(new_name)} | "
        f"ip={_sanitize_log_value(ip_address)}"
    )


def log_key_replace(username, key_name, success, ip_address):
    status = "SUCCESS" if success else "FAILED"
    audit_logger.info(
        f"KEY_REPLACE_{status} | user={_sanitize_log_value(username)} | "
        f"key={_sanitize_log_value(key_name)} | "
        f"ip={_sanitize_log_value(ip_address)}"
    )


def log_key_delete(username, key_name, ip_address):
    audit_logger.info(
        f"KEY_DELETE | user={_sanitize_log_value(username)} | "
        f"key={_sanitize_log_value(key_name)} | ip={_sanitize_log_value(ip_address)}"
    )

def log_rate_limit_exceeded(endpoint, ip_address, user=None):
    user_info = f" | user={_sanitize_log_value(user)}" if user else ""
    audit_logger.warning(
        f"RATE_LIMIT_EXCEEDED | endpoint={_sanitize_log_value(endpoint)} | "
        f"ip={_sanitize_log_value(ip_address)}{user_info}"
    )

def log_security_event(event, *, level=logging.INFO, **kwargs):
    """Write a structured security action without placing secrets in the log."""
    event_name = ''.join(
        character if character.isalnum() else '_'
        for character in str(event).upper()
    ).strip('_')[:96]
    safe_details = sanitize_audit_details(kwargs)
    details = ''.join(
        f" | {key}={_sanitize_log_value(value)}"
        for key, value in sorted(safe_details.items())
        if value is not None
    )
    audit_logger.log(level, f"{event_name}{details}")


def _iter_log_lines_newest_first(log_file, chunk_size=64 * 1024):
    """Yield a log file from its last line without loading it completely."""
    with open(log_file, 'rb') as fh:
        fh.seek(0, 2)
        position = fh.tell()
        pending = b''

        while position > 0:
            read_size = min(chunk_size, position)
            position -= read_size
            fh.seek(position)
            parts = (fh.read(read_size) + pending).split(b'\n')
            pending = parts[0]
            for line in reversed(parts[1:]):
                if line:
                    yield line.decode('utf-8', errors='replace')

        if pending:
            yield pending.decode('utf-8', errors='replace')


def read_audit_logs(offset=0, limit=100, level=None, q=None, max_scan=20000):
    """Read parsed audit log entries, newest first, for the admin viewer.

    Reads the active security audit log and its bounded rotated backups,
    scanning at most the newest `max_scan` lines across all files. Each line
    is one JSON object written by the StructuredFormatter. Malformed lines
    are skipped.

    Returns: {'items': [...], 'total': int, 'offset': int, 'limit': int}
    """
    if max_scan <= 0:
        return {'items': [], 'total': 0, 'offset': 0, 'limit': limit}

    log_file = LOGS_DIR / 'security_audit.log'
    raw_lines = []
    log_files = [log_file]
    from .app_settings import get_audit_backup_count
    log_files.extend(
        log_file.with_name(f'{log_file.name}.{index}')
        for index in range(1, get_audit_backup_count() + 1)
    )
    for candidate in log_files:
        try:
            for line in _iter_log_lines_newest_first(candidate):
                raw_lines.append(line)
                if len(raw_lines) >= max_scan:
                    break
        except FileNotFoundError:
            continue
        except OSError:
            continue
        if len(raw_lines) >= max_scan:
            break

    level_norm = level.upper() if level else None
    q_norm = q.lower() if q else None

    entries = []
    for line in raw_lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except (ValueError, TypeError):
            continue
        if level_norm and str(entry.get('level', '')).upper() != level_norm:
            continue
        if q_norm and q_norm not in line.lower():
            continue
        entries.append(entry)

    total = len(entries)
    try:
        offset = max(0, int(offset))
        limit = max(1, min(int(limit), 500))
    except (ValueError, TypeError):
        offset, limit = 0, 100
    page = entries[offset:offset + limit]
    return {'items': page, 'total': total, 'offset': offset, 'limit': limit}
