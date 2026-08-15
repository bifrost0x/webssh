import os
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa

_SESSION_DATA_DIRECTORY = tempfile.TemporaryDirectory(
    prefix='webssh-pytest-session-',
    ignore_cleanup_errors=True,
)
_SESSION_TEST_ROOT = Path(_SESSION_DATA_DIRECTORY.name)
_TEST_ENVIRONMENT = {
    'SECRET_KEY': 'test-secret-key-for-unit-tests-only',
    'OIDC_REDIRECT_URI': 'https://localhost/oidc/callback',
    'DEBUG': 'True',
    'DEPLOYMENT_PROFILE': 'homelab',
    'DATA_DIR': str(_SESSION_TEST_ROOT / 'data'),
    'TRANSFER_TEMP_DIR': str(_SESSION_TEST_ROOT / 'transfers'),
    'BACKUP_TEMP_DIR': str(_SESSION_TEST_ROOT / 'backups'),
    'RATELIMIT_STORAGE_URL': 'memory://',
    'LDAP_ENABLED': 'false',
    'LDAP_AUTO_PROVISION': 'false',
    'OIDC_ENABLED': 'false',
    'TAILSCALE_SSH_ENABLED': 'false',
}
_ORIGINAL_TEST_ENVIRONMENT = {
    name: os.environ.get(name)
    for name in _TEST_ENVIRONMENT
}


def _validate_real_redis_target():
    value = os.environ.get('TEST_REDIS_URL')
    if not value:
        return
    try:
        parsed = urlsplit(value)
        database = int(parsed.path.removeprefix('/'))
    except (TypeError, ValueError):
        parsed = None
        database = 0
    if (
        parsed is None
        or parsed.scheme not in {'redis', 'rediss'}
        or parsed.hostname not in {'localhost', '127.0.0.1', '::1'}
        or not parsed.path.startswith('/')
        or parsed.path.count('/') != 1
        or database <= 0
        or parsed.query
        or parsed.fragment
    ):
        raise pytest.UsageError(
            'TEST_REDIS_URL must use loopback and an explicit non-zero database'
        )


_validate_real_redis_target()
for _name, _value in _TEST_ENVIRONMENT.items():
    os.environ[_name] = _value


def pytest_unconfigure(config):
    del config
    for name, original in _ORIGINAL_TEST_ENVIRONMENT.items():
        if original is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = original
    _SESSION_DATA_DIRECTORY.cleanup()


@pytest.fixture
def app(monkeypatch):
    """Create Flask test application."""
    # ignore_cleanup_errors: on Windows the SQLite file can still be locked at
    # teardown; disposing the engine below handles the normal case, this is a
    # belt-and-suspenders guard so a stray handle never fails the test.
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        monkeypatch.setenv('DATA_DIR', tmpdir)
        # Re-import config to pick up test DATA_DIR
        import importlib
        import config
        importlib.reload(config)

        from app import app_settings, create_app
        monkeypatch.setattr(
            app_settings,
            '_SETTINGS_FILE',
            config.DATA_DIR / 'app_settings.json',
        )
        app = create_app()
        runtime_lifecycle = app.extensions['runtime_lifecycle']
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False

        from app.models import db
        with app.app_context():
            db.create_all()
            try:
                yield app
            finally:
                runtime_lifecycle.begin_shutdown(
                    config.RUNTIME_SHUTDOWN_GRACE_SECONDS
                )
                # Close all DB connections so the SQLite file is released before
                # the temp dir is removed (required on Windows, harmless on POSIX).
                db.session.remove()
                db.engine.dispose()


@pytest.fixture
def client(app):
    """Flask test client."""
    return app.test_client()


@pytest.fixture
def db_session(app):
    """Database session for direct DB operations."""
    from app.models import db
    with app.app_context():
        yield db.session


def _serialize_private_key(private_key, private_format,
                           encryption=serialization.NoEncryption()):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=private_format,
        encryption_algorithm=encryption,
    ).decode('utf-8')


@pytest.fixture
def rsa_private_key_pem():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _serialize_private_key(
        key,
        serialization.PrivateFormat.TraditionalOpenSSL,
    )


@pytest.fixture
def rsa_openssh_private_key_pem():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _serialize_private_key(key, serialization.PrivateFormat.OpenSSH)


@pytest.fixture
def ed25519_private_key_pem():
    key = ed25519.Ed25519PrivateKey.generate()
    return _serialize_private_key(key, serialization.PrivateFormat.OpenSSH)


@pytest.fixture
def ecdsa_private_key_pem():
    key = ec.generate_private_key(ec.SECP256R1())
    return _serialize_private_key(
        key,
        serialization.PrivateFormat.TraditionalOpenSSL,
    )


@pytest.fixture
def ecdsa_openssh_private_key_pem():
    key = ec.generate_private_key(ec.SECP256R1())
    return _serialize_private_key(key, serialization.PrivateFormat.OpenSSH)


@pytest.fixture
def dsa_private_key_pem():
    key = dsa.generate_private_key(key_size=2048)
    return _serialize_private_key(
        key,
        serialization.PrivateFormat.TraditionalOpenSSL,
    )


@pytest.fixture
def encrypted_rsa_private_key_pem():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _serialize_private_key(
        key,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.BestAvailableEncryption(b'test-passphrase'),
    )
