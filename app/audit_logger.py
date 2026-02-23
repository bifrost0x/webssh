import logging
import json
import sys
from pathlib import Path
from datetime import datetime
import config

LOGS_DIR = config.DATA_DIR / 'logs'
try:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
except PermissionError:
    import tempfile
    LOGS_DIR = Path(tempfile.gettempdir()) / 'webssh_logs'
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    print(f"⚠️  WARNING: Cannot write to {config.DATA_DIR / 'logs'}, using {LOGS_DIR}")

class StructuredFormatter(logging.Formatter):
    """JSON structured logging formatter for production."""

    def format(self, record):
        log_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
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

def setup_logger(name, log_file=None, level=logging.INFO):
    """Setup a logger with console and optional file output."""
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if logger.handlers:
        return logger

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)

    if config.DEBUG:
        console_handler.setFormatter(ConsoleFormatter())
    else:
        console_handler.setFormatter(StructuredFormatter())

    logger.addHandler(console_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(StructuredFormatter())
        logger.addHandler(file_handler)

    return logger

app_logger = setup_logger(
    'webssh',
    log_file=LOGS_DIR / 'app.log',
    level=logging.DEBUG if config.DEBUG else logging.INFO
)

audit_logger = setup_logger(
    'security_audit',
    log_file=LOGS_DIR / 'security_audit.log',
    level=logging.INFO
)

def log_info(message, **kwargs):
    """Log info message with optional structured data."""
    if kwargs:
        record = logging.LogRecord(
            'webssh', logging.INFO, '', 0, message, (), None
        )
        record.extra_data = kwargs
        app_logger.handle(record)
    else:
        app_logger.info(message)

def log_warning(message, **kwargs):
    """Log warning message with optional structured data."""
    if kwargs:
        record = logging.LogRecord(
            'webssh', logging.WARNING, '', 0, message, (), None
        )
        record.extra_data = kwargs
        app_logger.handle(record)
    else:
        app_logger.warning(message)

def log_error(message, exc_info=False, **kwargs):
    """Log error message with optional exception and structured data."""
    if kwargs:
        record = logging.LogRecord(
            'webssh', logging.ERROR, '', 0, message, (), None
        )
        record.extra_data = kwargs
        if exc_info:
            import sys
            record.exc_info = sys.exc_info()
        app_logger.handle(record)
    else:
        app_logger.error(message, exc_info=exc_info)

def log_debug(message, **kwargs):
    """Log debug message with optional structured data."""
    if kwargs:
        record = logging.LogRecord(
            'webssh', logging.DEBUG, '', 0, message, (), None
        )
        record.extra_data = kwargs
        app_logger.handle(record)
    else:
        app_logger.debug(message)

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
