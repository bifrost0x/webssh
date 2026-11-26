"""Run an isolated local WebSSH instance for Playwright.

The browser fixture data lives in ``seed.json`` (or the file named by
``WEBSSH_E2E_SEED``). This runner is the Python implementation of that seed
contract; tests/e2e/README.md describes what another backend has to apply.
"""

import json
import os
from pathlib import Path
import sys
import tempfile
from datetime import datetime, timezone
from werkzeug.serving import WSGIRequestHandler

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


DEFAULT_SEED_FILE = Path(__file__).resolve().with_name('seed.json')
SEED_VERSION = 1
# Hooks that need the seeded data and run before the server starts.
DATA_HOOKS = ('automation_ssh_peer', 'outbound_ssh_guard')
# Test-only Socket.IO events registered next to the real handlers.
SOCKET_HOOKS = ('socket_output_load', 'socket_workspace_restore', 'socket_herdr_sessions')


class FixtureRequestHandler(WSGIRequestHandler):
    """Keep HTTP errors visible without serializing thousands of success logs."""

    def log_request(self, code='-', size='-'):
        if str(code).isdigit() and int(code) < 400:
            return
        super().log_request(code, size)


def load_seed(path=None):
    """Read and minimally validate the language-neutral browser fixture seed."""
    seed_path = Path(path or os.environ.get('WEBSSH_E2E_SEED') or DEFAULT_SEED_FILE)
    seed = json.loads(seed_path.read_text(encoding='utf-8'))
    if not isinstance(seed, dict) or seed.get('version') != SEED_VERSION:
        raise RuntimeError(f'Unsupported E2E seed version in {seed_path}')
    refs = [account['ref'] for account in seed.get('accounts', [])]
    if len(refs) != len(set(refs)):
        raise RuntimeError('E2E seed account refs must be unique')
    for hook in seed.get('test_hooks', []):
        if hook.get('name') not in DATA_HOOKS + SOCKET_HOOKS:
            raise RuntimeError(f"Unknown E2E test hook: {hook.get('name')!r}")
    for name in seed.get('data_files', {}):
        if not name or Path(name).name != name or name in ('.', '..'):
            raise RuntimeError(f'E2E seed data file must be a plain file name: {name!r}')
    return seed


def seed_environment(seed, port, data_dir):
    """Expand the seed's configuration placeholders for this run."""
    environment = {}
    for name, value in seed.get('environment', {}).items():
        if value.startswith('{data_dir}/'):
            value = str(Path(data_dir) / value[len('{data_dir}/'):])
        environment[name] = value.replace('{port}', port)
    return environment


def _profile(name, host, username, auth_type, **extra):
    now = datetime.now(timezone.utc).isoformat()
    return {
        'id': name.lower().replace(' ', '-'),
        'name': name,
        'host': host,
        'port': 22,
        'username': username,
        'auth_type': auth_type,
        'key_id': extra.pop('key_id', None),
        'startup_mode': 'none',
        'created_at': now,
        'updated_at': now,
        **extra,
    }


def _by_account(items, accounts):
    """Group seed entries per account, keeping first-appearance order."""
    grouped = {}
    for item in items:
        grouped.setdefault(item['account'], []).append(item)
    return [(accounts[ref], entries) for ref, entries in grouped.items()]


def _resolve_references(entry, ids):
    """Replace symbolic seed references by the ids the backend assigned."""
    resolved = {}
    for field, value in entry.items():
        if field == 'account':
            continue
        if field in ('key', 'jump_host', 'socks_proxy'):
            resolved[f'{field}_id'] = ids[field][value]
        else:
            resolved[field] = value
    return resolved


def _generated_private_key(kind):
    if kind != 'ed25519':
        raise RuntimeError(f'Unsupported generated E2E key type: {kind!r}')
    return ed25519.Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode('utf-8')


def _seed_accounts(seed):
    from app.auth import register_user
    from app.user_settings import save_user_settings

    accounts = {}
    for account in seed.get('accounts', []):
        user, error = register_user(account['username'], account['password'])
        if error:
            raise RuntimeError(error)
        if account.get('admin'):
            user.is_admin = True
        accounts[account['ref']] = user
    for account in seed.get('accounts', []):
        if bool(accounts[account['ref']].is_admin) != bool(account.get('admin')):
            raise RuntimeError('E2E user roles were not seeded deterministically')
    # Accounts start with the tour already seen, so a spec that signs in
    # through the form does not depend on which spec ran first in its lane.
    # The onboarding spec sets the state it needs explicitly.
    settings = seed.get('account_settings')
    if settings:
        for user in accounts.values():
            if not save_user_settings(user.id, dict(settings)):
                raise RuntimeError('E2E tour state was not seeded')
    for account in seed.get('accounts', []):
        if account.get('mfa_enabled'):
            accounts[account['ref']].mfa_enabled = True
    return accounts


def _seed_identity_rows(seed, accounts):
    from app.models import (
        GitHubIdentity,
        OIDCIdentity,
        SecurityFeatureState,
        TOTPAuthenticator,
        WebAuthnCredential,
        db,
    )

    rows = []
    for identity in seed.get('external_identities', []):
        user_id = accounts[identity['account']].id
        if identity['provider'] == 'github':
            rows.append(GitHubIdentity(
                user_id=user_id,
                github_user_id=identity['github_user_id'],
                login=identity['login'],
            ))
        elif identity['provider'] == 'oidc':
            rows.append(OIDCIdentity(
                user_id=user_id,
                issuer=identity['issuer'],
                subject=identity['subject'],
            ))
        else:
            raise RuntimeError(f"Unknown E2E identity provider: {identity['provider']!r}")
    for feature in seed.get('security_features', []):
        rows.append(SecurityFeatureState(
            feature=feature['feature'],
            enabled=feature['enabled'],
            updated_by=accounts[feature['updated_by']].id,
        ))
    # Placeholders only mark the account as enrolled; they cannot authenticate.
    for factor in seed.get('mfa_placeholders', []):
        user_id = accounts[factor['account']].id
        if factor['type'] == 'totp':
            rows.append(TOTPAuthenticator(
                user_id=user_id,
                encrypted_secret=factor['secret'].encode('utf-8'),
                label=factor['label'],
                active=factor['active'],
            ))
        elif factor['type'] == 'passkey':
            rows.append(WebAuthnCredential(
                user_id=user_id,
                credential_id=factor['credential_id'].encode('utf-8'),
                public_key=factor['public_key'].encode('utf-8'),
                transports=json.dumps(factor['transports']),
                name=factor['name'],
            ))
        else:
            raise RuntimeError(f"Unknown E2E MFA placeholder: {factor['type']!r}")
    db.session.add_all(rows)
    db.session.commit()


def _seed_connections(seed, accounts):
    from app import (
        command_manager,
        command_set_manager,
        jump_host_manager,
        key_manager,
        profile_manager,
        socks_proxy_manager,
    )

    ids = {'key': {}, 'jump_host': {}, 'socks_proxy': {}}
    for entry in seed.get('ssh_keys', []):
        key, error = key_manager.save_key(
            accounts[entry['account']].id,
            entry['name'],
            _generated_private_key(entry['generate']),
        )
        if error:
            raise RuntimeError(error)
        ids['key'][entry['ref']] = key['id']
    for entry in seed.get('jump_hosts', []):
        jump_host, error = jump_host_manager.add_jump_host(
            accounts[entry['account']].id,
            entry['name'],
            entry['host'],
            entry['port'],
            entry['username'],
            entry['auth_type'],
            key_id=ids['key'][entry['key']] if 'key' in entry else entry.get('key_id'),
        )
        if error:
            raise RuntimeError(error)
        ids['jump_host'][entry['ref']] = jump_host['id']
    for entry in seed.get('socks_proxies', []):
        proxy, error = socks_proxy_manager.add_socks_proxy(
            accounts[entry['account']].id,
            entry['name'],
            entry['host'],
            entry['port'],
            auth_type=entry['auth_type'],
            username=entry['username'],
            remote_dns=entry['remote_dns'],
        )
        if error:
            raise RuntimeError(error)
        ids['socks_proxy'][entry['ref']] = proxy['id']

    now = datetime.now(timezone.utc).isoformat()
    for user, entries in _by_account(seed.get('commands', []), accounts):
        commands = [{
            **_resolve_references(entry, ids),
            'isSystem': False,
            'userId': user.id,
            'createdAt': now,
        } for entry in entries]
        if not command_manager.save_user_commands(user.id, commands):
            raise RuntimeError('Failed to seed E2E command')
    for user, entries in _by_account(seed.get('command_sets', []), accounts):
        command_sets = [{
            **_resolve_references(entry, ids),
            'created_at': now,
            'updated_at': now,
        } for entry in entries]
        saved, error = command_set_manager._save_command_sets(user.id, command_sets)
        if not saved:
            raise RuntimeError(error)
    for user, entries in _by_account(seed.get('profiles', []), accounts):
        profiles = []
        for entry in entries:
            fields = _resolve_references(entry, ids)
            profiles.append(_profile(
                fields.pop('name'),
                fields.pop('host'),
                fields.pop('username'),
                fields.pop('auth_type'),
                **fields,
            ))
        if not profile_manager.save_profiles(user.id, profiles):
            raise RuntimeError('Failed to seed E2E launcher profiles')


def _apply_admin_settings(seed):
    from app.app_settings import (
        set_automation_enabled,
        set_registration_enabled,
        update_admin_settings,
    )

    settings = dict(seed.get('admin_settings', {}))
    if 'automation_enabled' in settings:
        set_automation_enabled(settings.pop('automation_enabled'))
    if 'registration_enabled' in settings:
        set_registration_enabled(settings.pop('registration_enabled'))
    # Browser cases sign in to the same seeded accounts repeatedly.
    if settings:
        update_admin_settings(settings)


def _apply_data_hooks(seed, app, accounts):
    for hook in seed.get('test_hooks', []):
        if hook['name'] == 'automation_ssh_peer':
            from automation_fixture import seed as seed_automation_peer
            seed_automation_peer(app, [accounts[ref] for ref in hook['accounts']])
        elif hook['name'] == 'outbound_ssh_guard':
            from app import ssh_manager
            message = hook['error']

            def guarded_network_connect(**_kwargs):
                raise RuntimeError(message)

            ssh_manager.create_ssh_connection = guarded_network_connect


def _apply_socket_hooks(seed, socketio, app):
    for hook in seed.get('test_hooks', []):
        if hook['name'] == 'socket_output_load':
            from output_load import register_output_load
            register_output_load(socketio, app)
        elif hook['name'] == 'socket_workspace_restore':
            from workspace_restore import register_workspace_restore
            register_workspace_restore(socketio)
        elif hook['name'] == 'socket_herdr_sessions':
            from herdr_fixture import register_herdr_fixture
            register_herdr_fixture(socketio)


def apply_seed(seed, app):
    """Write the seed into the fresh DATA_DIR of ``app``; returns the accounts."""
    with app.app_context():
        _apply_admin_settings(seed)
        accounts = _seed_accounts(seed)
        _seed_identity_rows(seed, accounts)
        _seed_connections(seed, accounts)
        _apply_data_hooks(seed, app, accounts)
    return accounts


def _temporary_storage_environment(temporary_root):
    """Keep persistent data and operation scratch space in disjoint siblings."""
    root = Path(temporary_root).resolve()
    return {
        'DATA_DIR': str(root / 'data'),
        'BACKUP_TEMP_DIR': str(root / 'backups'),
        'TRANSFER_TEMP_DIR': str(root / 'transfers'),
    }


def main():
    project_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(project_root))
    seed = load_seed()
    port = os.environ.get('WEBSSH_E2E_PORT', '4173')
    with tempfile.TemporaryDirectory(
        prefix='webssh-e2e-',
        ignore_cleanup_errors=True,
    ) as temporary_root:
        storage_environment = _temporary_storage_environment(temporary_root)
        data_dir = storage_environment['DATA_DIR']
        Path(data_dir).mkdir(mode=0o700)
        for name, content in seed.get('data_files', {}).items():
            (Path(data_dir) / name).write_text(content, encoding='utf-8')
        os.environ.update({
            **storage_environment,
            **seed_environment(seed, port, data_dir),
        })

        if os.environ.get('WEBSSH_E2E_FAST_HASHING') == '1':
            from test_hashing import enable_fast_password_hashing
            enable_fast_password_hashing()

        # Exercise mutable Admin policies rather than pinning them via environment.
        for name in seed.get('unset_environment', []):
            os.environ.pop(name, None)

        from app import create_app, socketio

        app = create_app()
        apply_seed(seed, app)
        _apply_socket_hooks(seed, socketio, app)

        socketio.run(
            app,
            host='127.0.0.1',
            port=int(port),
            debug=False,
            use_reloader=False,
            allow_unsafe_werkzeug=True,
            request_handler=FixtureRequestHandler,
        )


if __name__ == '__main__':
    main()
