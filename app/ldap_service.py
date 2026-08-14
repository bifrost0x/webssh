"""Fail-closed LDAP lookup and bind boundary.

The optional Bonsai dependency is imported lazily so disabled installations do
not initialize LDAP code or touch directory secrets.
"""

from __future__ import annotations

import base64
import os
import ssl
import stat
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


_MAX_SECRET_BYTES = 16 * 1024
_MAX_CA_BYTES = 1024 * 1024


class LDAPUnavailable(RuntimeError):
    """Directory configuration, secret, or transport is unavailable."""


class LDAPLookupRejected(RuntimeError):
    """A user lookup did not resolve to exactly one safe identity."""


@dataclass(frozen=True)
class LDAPSettings:
    provider: str
    url: str
    base_dn: str
    bind_dn: str
    bind_password_file: Path
    ca_file: Path
    user_filter: str
    unique_id_attribute: str
    connect_timeout: int
    operation_timeout: int

    @classmethod
    def from_config(cls):
        import config

        return cls(
            provider=getattr(config, 'LDAP_PROVIDER_ID', 'default'),
            url=config.LDAP_URL,
            base_dn=config.LDAP_BASE_DN,
            bind_dn=config.LDAP_BIND_DN,
            bind_password_file=Path(config.LDAP_BIND_PASSWORD_FILE),
            ca_file=Path(config.LDAP_CA_FILE),
            user_filter=config.LDAP_USER_FILTER,
            unique_id_attribute=config.LDAP_UNIQUE_ID_ATTRIBUTE,
            connect_timeout=config.LDAP_CONNECT_TIMEOUT,
            operation_timeout=config.LDAP_OPERATION_TIMEOUT,
        )


@dataclass(frozen=True)
class LDAPIdentity:
    provider: str
    subject: str
    distinguished_name: str


def escape_filter_value(value):
    """Escape one assertion value according to RFC 4515 section 3."""
    escaped = []
    for byte in str(value).encode('utf-8'):
        if byte in {0x00, 0x28, 0x29, 0x2A, 0x5C} or byte >= 0x80:
            escaped.append(f'\\{byte:02x}')
        else:
            escaped.append(chr(byte))
    return ''.join(escaped)


def _read_secret(path):
    secret_path = Path(path)
    try:
        metadata = secret_path.lstat()
        if secret_path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise LDAPUnavailable('LDAP secret path is not a regular file')
        if os.name != 'nt' and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise LDAPUnavailable('LDAP secret file permissions are too broad')
        with secret_path.open('rb') as secret_file:
            content = secret_file.read(_MAX_SECRET_BYTES + 1)
    except LDAPUnavailable:
        raise
    except OSError as exc:
        raise LDAPUnavailable('LDAP secret file is unavailable') from exc
    if len(content) > _MAX_SECRET_BYTES:
        raise LDAPUnavailable('LDAP secret file exceeds the size limit')
    content = content.rstrip(b'\r\n')
    if not content or b'\x00' in content:
        raise LDAPUnavailable('LDAP secret file is invalid')
    try:
        return content.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise LDAPUnavailable('LDAP secret file is not UTF-8') from exc


def _canonical_subject(value):
    if isinstance(value, (bytes, bytearray, memoryview)):
        encoded = base64.urlsafe_b64encode(bytes(value)).decode('ascii')
        result = f'b64:{encoded.rstrip("=")}'
    else:
        result = str(value).strip()
    if not result or len(result) > 512 or '\x00' in result:
        raise LDAPLookupRejected('LDAP identity attribute is invalid')
    return result


def _canonical_distinguished_name(value):
    result = str(value).strip()
    if not result or len(result) > 2048 or '\x00' in result:
        raise LDAPLookupRejected('LDAP distinguished name is invalid')
    return result


def validate_runtime_files(settings=None):
    """Fail before serving when enabled LDAP secrets are unusable."""
    active_settings = settings or LDAPSettings.from_config()
    _read_secret(active_settings.bind_password_file)
    ca_path = Path(active_settings.ca_file)
    try:
        metadata = ca_path.lstat()
        if ca_path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise LDAPUnavailable('LDAP CA path is not a regular file')
        if metadata.st_size <= 0 or metadata.st_size > _MAX_CA_BYTES:
            raise LDAPUnavailable('LDAP CA bundle has an invalid size')
        ca_data = ca_path.read_text(encoding='ascii')
        ssl.create_default_context(cadata=ca_data)
    except LDAPUnavailable:
        raise
    except (OSError, UnicodeDecodeError, ssl.SSLError, ValueError) as exc:
        raise LDAPUnavailable('LDAP CA bundle is unavailable or invalid') from exc


class BonsaiBackend:
    """Narrow synchronous adapter around Bonsai's libldap client."""

    def __init__(self, bonsai_module=None):
        self._bonsai_module = bonsai_module

    @property
    def bonsai(self):
        if self._bonsai_module is None:
            try:
                import bonsai
            except ImportError as exc:
                raise LDAPUnavailable('LDAP client dependency is unavailable') from exc
            self._bonsai_module = bonsai
        return self._bonsai_module

    def _client(self, settings, bind_dn, password):
        bonsai = self.bonsai
        use_starttls = urlsplit(settings.url).scheme == 'ldap'
        client = bonsai.LDAPClient(settings.url, tls=use_starttls)
        client.set_ca_cert(str(settings.ca_file))
        client.set_cert_policy('demand')
        client.set_ignore_referrals(True)
        client.set_server_chase_referrals(False)
        client.set_credentials('SIMPLE', user=bind_dn, password=password)
        return client

    def search_user(self, settings, bind_password, filter_expression):
        bonsai = self.bonsai
        client = self._client(settings, settings.bind_dn, bind_password)
        connection = None
        try:
            connection = client.connect(timeout=settings.connect_timeout)
            entries = connection.search(
                settings.base_dn,
                bonsai.LDAPSearchScope.SUBTREE,
                filter_expression,
                [settings.unique_id_attribute],
                timeout=settings.operation_timeout,
                sizelimit=2,
            )
        except bonsai.LDAPError as exc:
            raise LDAPUnavailable('LDAP lookup failed') from exc
        finally:
            if connection is not None:
                connection.close(abandon_requests=True)

        identities = []
        for entry in entries:
            try:
                values = entry[settings.unique_id_attribute]
            except (KeyError, TypeError) as exc:
                raise LDAPLookupRejected(
                    'LDAP identity attribute is missing'
                ) from exc
            if len(values) != 1:
                raise LDAPLookupRejected(
                    'LDAP identity attribute must have exactly one value'
                )
            identities.append(LDAPIdentity(
                provider=settings.provider,
                subject=_canonical_subject(values[0]),
                distinguished_name=str(entry.dn),
            ))
        return identities

    def probe(self, settings, bind_password):
        bonsai = self.bonsai
        client = self._client(settings, settings.bind_dn, bind_password)
        connection = None
        try:
            connection = client.connect(timeout=settings.connect_timeout)
            return True
        except bonsai.LDAPError as exc:
            raise LDAPUnavailable('LDAP readiness probe failed') from exc
        finally:
            if connection is not None:
                connection.close(abandon_requests=True)

    def verify_password(self, settings, distinguished_name, password):
        bonsai = self.bonsai
        client = self._client(settings, distinguished_name, password)
        connection = None
        try:
            connection = client.connect(timeout=settings.connect_timeout)
            return True
        except bonsai.AuthenticationError:
            return False
        except bonsai.LDAPError as exc:
            raise LDAPUnavailable('LDAP bind failed') from exc
        finally:
            if connection is not None:
                connection.close(abandon_requests=True)


class LDAPDirectory:
    """Resolve and verify identities without retaining any credentials."""

    def __init__(self, settings=None, *, backend=None):
        self.settings = settings or LDAPSettings.from_config()
        self.backend = backend or BonsaiBackend()

    def lookup(self, username):
        normalized_username = str(username or '').strip()
        if not normalized_username or len(normalized_username) > 256:
            raise LDAPLookupRejected('LDAP username is invalid')
        filter_expression = self.settings.user_filter.format(
            username=escape_filter_value(normalized_username),
        )
        bind_password = _read_secret(self.settings.bind_password_file)
        try:
            entries = self.backend.search_user(
                self.settings,
                bind_password,
                filter_expression,
            )
        finally:
            bind_password = None
        if len(entries) != 1:
            raise LDAPLookupRejected(
                'LDAP lookup must return exactly one identity'
            )
        entry = entries[0]
        if isinstance(entry, LDAPIdentity):
            subject = entry.subject
            distinguished_name = entry.distinguished_name
        else:
            subject = entry.subject
            distinguished_name = entry.dn
        return LDAPIdentity(
            provider=self.settings.provider,
            subject=_canonical_subject(subject),
            distinguished_name=_canonical_distinguished_name(
                distinguished_name,
            ),
        )

    def verify_password(self, distinguished_name, password):
        if not password:
            return False
        return bool(self.backend.verify_password(
            self.settings,
            distinguished_name,
            password,
        ))

    def probe(self):
        bind_password = _read_secret(self.settings.bind_password_file)
        try:
            return bool(self.backend.probe(self.settings, bind_password))
        finally:
            bind_password = None
