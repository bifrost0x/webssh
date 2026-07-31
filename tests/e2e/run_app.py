"""Run an isolated local WebSSH instance for Playwright."""

import os
from pathlib import Path
import sys
import tempfile
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


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


def _seed_launcher_profiles(admin, user):
    from app import key_manager, profile_manager

    private_key = ed25519.Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode('utf-8')
    key, error = key_manager.save_key(admin.id, 'E2E usable key', private_key)
    if error:
        raise RuntimeError(error)

    admin_profiles = [
        _profile('Password review', 'password.local', 'passworduser', 'password'),
        _profile('Usable key', 'key.local', 'keyuser', 'key', key_id=key['id']),
        _profile('Missing key', 'missing-key.local', 'keyuser', 'key', key_id='missing-key'),
        _profile(
            'Missing jump host',
            'missing-jump.local',
            'keyuser',
            'key',
            key_id=key['id'],
            jump_host_id='missing-jump-host',
        ),
        _profile('Authorized Tailscale', 'tail-node', 'root', 'tailscale'),
    ]
    if not profile_manager.save_profiles(admin.id, admin_profiles):
        raise RuntimeError('Failed to seed admin launcher profiles')
    if not profile_manager.save_profiles(user.id, [
        _profile('Unauthorized Tailscale', 'tail-node', 'root', 'tailscale'),
    ]):
        raise RuntimeError('Failed to seed unauthorized launcher profile')
    return key


def _seed_post_connect_profiles(admin, key):
    from app import command_manager, command_set_manager, profile_manager

    command = {
        'id': 'e2e-command',
        'name': 'E2E command',
        'command': 'printf',
        'parameters': '--default',
        'description': 'Disposable browser-test command',
        'os': ['all'],
        'category': 'custom',
        'isSystem': False,
        'userId': admin.id,
        'createdAt': datetime.now(timezone.utc).isoformat(),
    }
    guarded_command = {
        **command,
        'id': 'guarded-direct-command',
        'name': 'Guarded direct command',
        'command': 'whoami',
        'parameters': '',
    }
    if not command_manager.save_user_commands(admin.id, [command, guarded_command]):
        raise RuntimeError('Failed to seed E2E command')

    now = datetime.now(timezone.utc).isoformat()
    command_set = {
        'id': 'e2e-command-set',
        'name': 'E2E command set',
        'description': 'Disposable browser-test set',
        'use_sudo': False,
        'steps': [{'type': 'inline', 'command': 'printf set'}],
        'created_at': now,
        'updated_at': now,
    }
    guarded_set = {
        **command_set,
        'id': 'guarded-profile-set',
        'name': 'Guarded profile set',
        'steps': [{'type': 'inline', 'command': 'whoami'}],
    }
    saved, error = command_set_manager._save_command_sets(
        admin.id,
        [command_set, guarded_set],
    )
    if not saved:
        raise RuntimeError(error)

    profiles = profile_manager.load_profiles(admin.id)
    common = {
        'username': 'postuser',
        'auth_type': 'key',
        'key_id': key['id'],
    }
    profiles.extend([
        _profile('Post none', 'post-none.local', **common),
        _profile(
            'Post free text',
            'post-free.local',
            **common,
            startup_mode='free_text',
            startup_commands='printf free-text',
        ),
        _profile(
            'Post command default',
            'post-default.local',
            **common,
            startup_mode='command',
            command_id='e2e-command',
        ),
        _profile(
            'Post command empty',
            'post-empty.local',
            **common,
            startup_mode='command',
            command_id='e2e-command',
            parameters_override='',
        ),
        _profile(
            'Post command custom',
            'post-custom.local',
            **common,
            startup_mode='command',
            command_id='e2e-command',
            parameters_override='--custom value',
        ),
        _profile(
            'Post command set',
            'post-set.local',
            **common,
            startup_mode='command_set',
            command_set_id='e2e-command-set',
        ),
        _profile(
            'Post missing command',
            'post-missing-command.local',
            **common,
            startup_mode='command',
            command_id='missing-command',
        ),
        _profile(
            'Post missing command set',
            'post-missing-set.local',
            **common,
            startup_mode='command_set',
            command_set_id='missing-command-set',
        ),
        _profile(
            'Guarded direct command profile',
            'guarded-command.local',
            **common,
            startup_mode='command',
            command_id='guarded-direct-command',
        ),
        _profile(
            'Guarded command set profile',
            'guarded-set.local',
            **common,
            startup_mode='command_set',
            command_set_id='guarded-profile-set',
        ),
    ])
    if not profile_manager.save_profiles(admin.id, profiles):
        raise RuntimeError('Failed to seed post-connect profiles')


def main():
    project_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(project_root))
    with tempfile.TemporaryDirectory(
        prefix='webssh-e2e-',
        ignore_cleanup_errors=True,
    ) as data_dir:
        oidc_secret = Path(data_dir) / 'oidc-client-secret'
        oidc_secret.write_text('e2e-only-oidc-secret', encoding='utf-8')
        os.environ.update({
            'DATA_DIR': data_dir,
            'SECRET_KEY': 'e2e-only-secret-key',
            'DEBUG': 'False',
            'HOST': '127.0.0.1',
            'PORT': os.environ.get('WEBSSH_E2E_PORT', '4173'),
            'REGISTRATION_ENABLED': 'False',
            'RATELIMIT_STORAGE_URL': 'memory://',
            'RATELIMIT_LOGIN_LIMIT': '100 per minute',
            'CORS_ORIGINS': (
                'http://127.0.0.1:'
                + os.environ.get('WEBSSH_E2E_PORT', '4173')
            ),
            'WEBAUTHN_ENABLED': 'true',
            'WEBAUTHN_RP_ID': 'localhost',
            'WEBAUTHN_RP_NAME': 'WebSSH E2E',
            'WEBAUTHN_ORIGIN': (
                'http://localhost:'
                + os.environ.get('WEBSSH_E2E_PORT', '4173')
            ),
            'OIDC_ENABLED': 'true',
            'OIDC_ISSUER': 'https://issuer.example',
            'OIDC_CLIENT_ID': 'webssh-e2e',
            'OIDC_CLIENT_SECRET_FILE': str(oidc_secret),
            'TAILSCALE_SSH_ENABLED': 'true',
            'TAILSCALE_SSH_ALLOWED_TARGETS': 'tail-node',
            'TAILSCALE_SSH_ALLOWED_REMOTE_USERS': 'root',
        })

        from app import create_app, socketio
        from app.auth import register_user

        app = create_app()
        with app.app_context():
            from app.models import OIDCIdentity, db

            admin, error = register_user('e2e_admin', 'browser-password')
            if error:
                raise RuntimeError(error)
            admin.is_admin = True
            user, error = register_user('e2e_user', 'browser-password')
            if error:
                raise RuntimeError(error)
            if not admin.is_admin or user.is_admin:
                raise RuntimeError('E2E user roles were not seeded deterministically')
            db.session.add(OIDCIdentity(
                user_id=user.id,
                issuer='https://issuer.example',
                subject='existing-e2e-subject',
            ))
            db.session.commit()
            key = _seed_launcher_profiles(admin, user)
            _seed_post_connect_profiles(admin, key)

            from app import ssh_manager

            def guarded_network_connect(**_kwargs):
                raise RuntimeError('E2E network guard reached')

            ssh_manager.create_ssh_connection = guarded_network_connect

        socketio.run(
            app,
            host='127.0.0.1',
            port=int(os.environ.get('WEBSSH_E2E_PORT', '4173')),
            debug=False,
            use_reloader=False,
            allow_unsafe_werkzeug=True,
        )


if __name__ == '__main__':
    main()
