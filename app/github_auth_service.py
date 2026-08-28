"""Runtime GitHub App configuration, OAuth state, and provider API access."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from threading import Lock
from urllib.parse import urlencode, urlsplit

import requests
import config

from .github_auth_crypto import decrypt_client_secret, encrypt_client_secret
from .models import (
    GitHubAuthConfiguration,
    GitHubOAuthState,
    as_naive_utc,
    db,
)


AUTHORIZE_URL = 'https://github.com/login/oauth/authorize'
TOKEN_URL = 'https://github.com/login/oauth/access_token'
API_URL = 'https://api.github.com'
API_VERSION = '2022-11-28'
HTTP_TIMEOUT = 5
_STATE_TTL = timedelta(minutes=5)
_state_lock = Lock()
_CLIENT_ID_PATTERN = re.compile(r'^[A-Za-z0-9_-]{8,128}$')
_ORG_PATTERN = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$')
_PURPOSES = frozenset({'login', 'link', 'step_up'})


class GitHubConfigurationError(ValueError):
    """Raised when an administrator supplies unsafe provider settings."""


class GitHubStateError(ValueError):
    """Raised for missing, expired, replayed, or mismatched OAuth state."""


class GitHubProviderError(RuntimeError):
    """Raised when GitHub cannot be safely queried."""


class GitHubOrganizationRejected(PermissionError):
    """Raised when the authenticated identity is outside the allowlist."""


@dataclass(frozen=True)
class GitHubSettings:
    enabled: bool
    client_id: str
    client_secret: str | None
    secret_configured: bool
    redirect_uri: str
    auto_provision: bool
    allowed_orgs: tuple[str, ...]
    generation: int
    error: str | None

    @property
    def active(self):
        return self.enabled and self.error is None

    def public_dict(self):
        return {
            'enabled': self.enabled,
            'active': self.active,
            'client_id': self.client_id,
            'client_secret_configured': self.secret_configured,
            'redirect_uri': self.redirect_uri,
            'auto_provision': self.auto_provision,
            'allowed_orgs': list(self.allowed_orgs),
            'generation': self.generation,
            'error': self.error,
        }


@dataclass(frozen=True)
class GitHubIntent:
    code_verifier: str
    purpose: str
    user_id: int | None
    step_up_intent_id: int | None
    continuation: str
    configuration_generation: int


@dataclass(frozen=True)
class GitHubProfile:
    user_id: str
    login: str
    display_name: str | None


def _hash(value):
    return hashlib.sha256(str(value).encode('utf-8')).hexdigest()


def _safe_continuation(value):
    candidate = str(value or '/')
    parsed = urlsplit(candidate)
    if (
        not candidate.startswith('/')
        or candidate.startswith('//')
        or '\\' in candidate
        or parsed.scheme
        or parsed.netloc
        or parsed.fragment
        or len(candidate) > 512
    ):
        return '/'
    return candidate


def _normalize_orgs(value):
    if isinstance(value, str):
        values = value.split(',')
    elif isinstance(value, (list, tuple)):
        values = value
    else:
        raise GitHubConfigurationError('allowed_orgs must be a list')
    result = []
    for raw in values:
        if not isinstance(raw, str):
            raise GitHubConfigurationError(
                'allowed_orgs must contain only organization names'
            )
        org = str(raw or '').strip().lower()
        if not org:
            continue
        if not _ORG_PATTERN.fullmatch(org):
            raise GitHubConfigurationError('allowed_orgs contains an invalid organization')
        if org not in result:
            result.append(org)
    if len(result) > 50:
        raise GitHubConfigurationError('allowed_orgs contains too many organizations')
    return tuple(result)


def _validate_redirect_uri(value):
    uri = str(value or '').strip()
    try:
        parsed = urlsplit(uri)
        port = parsed.port
    except ValueError as exc:
        raise GitHubConfigurationError('redirect_uri is invalid') from exc
    del port
    loopback = parsed.hostname in {'localhost', '127.0.0.1', '::1'}
    application_root = str(getattr(config, 'APPLICATION_ROOT', '') or '').rstrip('/')
    expected_path = f'{application_root}/auth/github/callback'
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != expected_path
        or parsed.query
        or parsed.fragment
        or not (parsed.scheme == 'https' or (parsed.scheme == 'http' and loopback))
    ):
        raise GitHubConfigurationError(
            'redirect_uri must be the exact HTTPS URL for /auth/github/callback'
        )
    if len(uri) > 2048:
        raise GitHubConfigurationError('redirect_uri is too long')
    return uri


def _configuration_row():
    return db.session.get(GitHubAuthConfiguration, 1)


def get_settings(*, include_secret=False):
    row = _configuration_row()
    if row is None:
        return GitHubSettings(False, '', None, False, '', False, (), 0, None)
    try:
        raw_orgs = json.loads(row.allowed_orgs_json or '[]')
        orgs = _normalize_orgs(raw_orgs)
    except (TypeError, ValueError, json.JSONDecodeError):
        orgs = ()
        error = 'Stored organization policy is invalid.'
    else:
        error = None
    secret = None
    secret_configured = bool(row.encrypted_client_secret)
    if include_secret and secret_configured:
        try:
            secret = decrypt_client_secret(row.encrypted_client_secret)
        except Exception as exc:
            raise GitHubConfigurationError(
                'Stored GitHub client secret cannot be decrypted'
            ) from exc
    if row.enabled:
        if not _CLIENT_ID_PATTERN.fullmatch(row.client_id or ''):
            error = error or 'GitHub client ID is missing or invalid.'
        if not secret_configured:
            error = error or 'GitHub client secret is missing.'
        try:
            _validate_redirect_uri(row.redirect_uri)
        except GitHubConfigurationError as exc:
            error = error or str(exc)
    return GitHubSettings(
        bool(row.enabled), row.client_id or '', secret, secret_configured,
        row.redirect_uri or '', bool(row.auto_provision), orgs,
        int(row.generation or 0), error,
    )


def github_auth_is_active():
    try:
        return get_settings().active
    except Exception:
        return False


def update_settings(data, admin_id):
    if not isinstance(data, dict):
        raise GitHubConfigurationError('Invalid GitHub configuration payload')
    allowed = {
        'enabled', 'client_id', 'client_secret', 'redirect_uri',
        'auto_provision', 'allowed_orgs', 'clear_client_secret',
    }
    if not data or set(data) - allowed:
        raise GitHubConfigurationError('Invalid GitHub configuration payload')
    row = _configuration_row()
    if row is None:
        row = GitHubAuthConfiguration(id=1)
        db.session.add(row)
    if 'enabled' in data:
        if type(data['enabled']) is not bool:
            raise GitHubConfigurationError('enabled must be a boolean')
        row.enabled = data['enabled']
    if 'auto_provision' in data:
        if type(data['auto_provision']) is not bool:
            raise GitHubConfigurationError('auto_provision must be a boolean')
        row.auto_provision = data['auto_provision']
    if 'client_id' in data:
        if not isinstance(data['client_id'], str):
            raise GitHubConfigurationError('client_id must be a string')
        client_id = data['client_id'].strip()
        if client_id and not _CLIENT_ID_PATTERN.fullmatch(client_id):
            raise GitHubConfigurationError('client_id is invalid')
        row.client_id = client_id
    if 'redirect_uri' in data:
        if not isinstance(data['redirect_uri'], str):
            raise GitHubConfigurationError('redirect_uri must be a string')
        value = data['redirect_uri'].strip()
        row.redirect_uri = _validate_redirect_uri(value) if value else ''
    if 'allowed_orgs' in data:
        row.allowed_orgs_json = json.dumps(
            _normalize_orgs(data['allowed_orgs']), separators=(',', ':')
        )
    if (
        'clear_client_secret' in data
        and type(data['clear_client_secret']) is not bool
    ):
        raise GitHubConfigurationError('clear_client_secret must be a boolean')
    if data.get('clear_client_secret') is True:
        row.encrypted_client_secret = None
        row.secret_updated_at = datetime.now(timezone.utc)
    if 'client_secret' in data:
        if not isinstance(data['client_secret'], str):
            raise GitHubConfigurationError('client_secret must be a string')
        secret = data['client_secret']
    else:
        secret = ''
    if secret:
        if not 20 <= len(secret) <= 512 or '\n' in secret or '\r' in secret:
            raise GitHubConfigurationError('client_secret is invalid')
        row.encrypted_client_secret = encrypt_client_secret(secret)
        row.secret_updated_at = datetime.now(timezone.utc)
    row.updated_by = int(admin_id)
    row.updated_at = datetime.now(timezone.utc)
    row.generation = int(row.generation or 0) + 1
    db.session.flush()
    effective = get_settings()
    if row.enabled and not effective.active:
        raise GitHubConfigurationError(effective.error or 'GitHub configuration is incomplete')
    GitHubOAuthState.query.delete(synchronize_session=False)
    db.session.commit()
    return get_settings()


def create_oauth_state(
    *, state, session_binding, code_verifier, purpose, generation,
    user_id=None, step_up_intent_id=None, continuation='/', now=None,
):
    if purpose not in _PURPOSES:
        raise GitHubStateError('OAuth purpose is invalid')
    if any(len(str(value or '')) < 8 for value in (state, session_binding, code_verifier)):
        raise GitHubStateError('OAuth state values are invalid')
    if purpose == 'login' and (user_id is not None or step_up_intent_id is not None):
        raise GitHubStateError('Login state contains account context')
    if purpose == 'link' and (not isinstance(user_id, int) or step_up_intent_id is not None):
        raise GitHubStateError('Link state is invalid')
    if purpose == 'step_up' and (user_id is not None or not isinstance(step_up_intent_id, int)):
        raise GitHubStateError('Step-up state is invalid')
    now = as_naive_utc(now or datetime.now(timezone.utc))
    with _state_lock:
        GitHubOAuthState.query.filter(GitHubOAuthState.expires_at < now).delete(
            synchronize_session=False
        )
        row = GitHubOAuthState(
            state_hash=_hash(state),
            session_binding_hash=_hash(session_binding),
            code_verifier=code_verifier,
            purpose=purpose,
            user_id=user_id,
            step_up_intent_id=step_up_intent_id,
            continuation=_safe_continuation(continuation),
            configuration_generation=int(generation),
            expires_at=now + _STATE_TTL,
        )
        db.session.add(row)
        db.session.commit()
    return row


def consume_oauth_state(*, state, session_binding, generation, now=None):
    now = as_naive_utc(now or datetime.now(timezone.utc))
    with _state_lock:
        row = GitHubOAuthState.query.filter_by(
            state_hash=_hash(state),
            session_binding_hash=_hash(session_binding),
        ).first()
        if row is None:
            raise GitHubStateError('OAuth state is unavailable')
        intent = GitHubIntent(
            row.code_verifier, row.purpose, row.user_id,
            row.step_up_intent_id, _safe_continuation(row.continuation),
            row.configuration_generation,
        )
        expires_at = row.expires_at
        db.session.delete(row)
        db.session.commit()
    if expires_at < now or intent.configuration_generation != int(generation):
        raise GitHubStateError('OAuth state is expired')
    return intent


def authorization_url(settings, *, state, code_challenge):
    return f'{AUTHORIZE_URL}?{urlencode({
        "client_id": settings.client_id,
        "redirect_uri": settings.redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    })}'


def _headers(token=None):
    headers = {
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': API_VERSION,
        'User-Agent': 'WebSSH-GitHub-Authentication',
    }
    if token:
        headers['Authorization'] = f'Bearer {token}'
    return headers


def exchange_code(settings, *, code, code_verifier, http=requests):
    if not code or len(code) > 1024:
        raise GitHubProviderError('Authorization code is invalid')
    try:
        response = http.post(
            TOKEN_URL,
            headers=_headers(),
            data={
                'client_id': settings.client_id,
                'client_secret': settings.client_secret,
                'code': code,
                'redirect_uri': settings.redirect_uri,
                'code_verifier': code_verifier,
            },
            timeout=HTTP_TIMEOUT,
            allow_redirects=False,
        )
        payload = response.json()
    except Exception as exc:
        raise GitHubProviderError('Token exchange failed') from exc
    token = payload.get('access_token') if isinstance(payload, dict) else None
    if response.status_code != 200 or not isinstance(token, str) or not token:
        raise GitHubProviderError('Token exchange failed')
    return token


def fetch_profile(token, *, http=requests):
    try:
        response = http.get(
            f'{API_URL}/user', headers=_headers(token), timeout=HTTP_TIMEOUT,
            allow_redirects=False,
        )
        payload = response.json()
    except Exception as exc:
        raise GitHubProviderError('GitHub profile request failed') from exc
    user_id = payload.get('id') if isinstance(payload, dict) else None
    login = payload.get('login') if isinstance(payload, dict) else None
    if (
        response.status_code != 200
        or type(user_id) is not int
        or user_id <= 0
        or not isinstance(login, str)
        or not login
        or len(login) > 128
    ):
        raise GitHubProviderError('GitHub profile response is invalid')
    name = payload.get('name')
    if not isinstance(name, str) or not name or len(name) > 256:
        name = None
    return GitHubProfile(str(user_id), login, name)


def enforce_organization_policy(token, settings, *, http=requests):
    if not settings.allowed_orgs:
        return
    uncertain = False
    for org in settings.allowed_orgs:
        try:
            response = http.get(
                f'{API_URL}/user/memberships/orgs/{org}',
                headers=_headers(token),
                timeout=HTTP_TIMEOUT,
                allow_redirects=False,
            )
            payload = response.json() if response.status_code == 200 else {}
        except Exception:
            uncertain = True
            continue
        if response.status_code == 200 and payload.get('state') == 'active':
            return
        if response.status_code not in {200, 404}:
            uncertain = True
    if uncertain:
        raise GitHubProviderError('Organization membership could not be verified')
    raise GitHubOrganizationRejected('GitHub organization membership is required')
