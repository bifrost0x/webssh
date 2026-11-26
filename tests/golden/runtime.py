"""Fixed parameters and application start-up shared by generator and tests."""

import datetime as _dt
import importlib
import os
import pkgutil
import re
from pathlib import Path

from .determinism import SeededStream

SEED = 'webssh-golden-data-set-v1'
# Every timestamp in the fixture derives from this instant.
START = _dt.datetime(2026, 11, 2, 9, 0, 0, tzinfo=_dt.timezone.utc)
RP_ID = 'webssh.golden.test'
ORIGIN = 'https://webssh.golden.test'
CONFIG_ADMIN = 'cfg_admin'
BCRYPT_ROUNDS = 12  # bcrypt.gensalt() default, used by User.set_password

GOLDEN_ROOT = Path(__file__).resolve().parent
FIXTURE_ROOT = GOLDEN_ROOT / 'fixture'
# The DATA_DIR travels as one tar: the repository hygiene check rejects
# tracked data/ directories, *.db, *.pem, *.log, secret_key and known_hosts.
DATA_ARCHIVE = 'datadir.tar'


def secret_key():
    """The fixture's SECRET_KEY: 64 hex characters from the seeded stream."""
    return SeededStream(SEED, 'secret-key').read(32).hex()


def environment(data_dir, work_dir):
    """Process environment for a production-like homelab instance."""
    work_dir = Path(work_dir)
    return {
        'SECRET_KEY': secret_key(),
        'DATA_DIR': str(data_dir),
        'TRANSFER_TEMP_DIR': str(work_dir / 'transfers'),
        'BACKUP_TEMP_DIR': str(work_dir / 'backup-work'),
        'BACKUP_RECOVERY_DURABLE': 'true',
        'DEBUG': 'false',
        'DEPLOYMENT_PROFILE': 'homelab',
        'SESSION_COOKIE_SECURE': 'false',
        'RATELIMIT_STORAGE_URL': 'memory://',
        'WEBAUTHN_ENABLED': 'true',
        'WEBAUTHN_RP_ID': RP_ID,
        'WEBAUTHN_ORIGIN': ORIGIN,
        'TOTP_ENABLED': 'true',
        'RECOVERY_CODES_ENABLED': 'true',
        'ADMIN_USERS': CONFIG_ADMIN,
        'LDAP_ENABLED': 'false',
        'LDAP_AUTO_PROVISION': 'false',
        'OIDC_ENABLED': 'false',
        'TAILSCALE_SSH_ENABLED': 'false',
        'TZ': 'UTC',
    }


def import_application_modules():
    """Import every app module so the clock patch reaches all bindings."""
    import app
    for module in pkgutil.iter_modules(app.__path__, 'app.'):
        importlib.import_module(module.name)


def reload_config():
    import config
    importlib.reload(config)
    from app import app_settings
    app_settings._SETTINGS_FILE = config.DATA_DIR / 'app_settings.json'
    return config


def create_application():
    """The real Flask app without background workers."""
    from app import create_app
    return create_app(start_runtime=False)


def shutdown(application):
    import config
    from app.models import db
    application.extensions['runtime_lifecycle'].begin_shutdown(
        config.RUNTIME_SHUTDOWN_GRACE_SECONDS
    )
    with application.app_context():
        db.session.remove()
        db.engine.dispose()


_CSRF_PATTERN = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"')


def csrf_token(client, path='/login'):
    response = client.get(path)
    page = response.get_data(as_text=True)
    match = _CSRF_PATTERN.search(page)
    if match is None:
        raise RuntimeError(f"no CSRF token on {path}: {response.status_code} {page[:300]!r}")
    return match.group(1)


def password_login(client, username, password):
    """POST the real login form, CSRF token included."""
    token = csrf_token(client)
    return client.post('/login', data={
        'username': username,
        'password': password,
        'csrf_token': token,
    })


def apply_environment(values):
    os.environ.update(values)
    import time
    time.tzset()
