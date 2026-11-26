"""Accounts of every authentication kind, built through the application code.

Directory, GitHub and OIDC identities need an external provider for the
interactive flow. Their rows are created with the same model fields and the
same side effects as the corresponding route, cited per function, so the
stored data matches a real link or provisioning.
"""

import secrets

from . import runtime

OIDC_ISSUER = 'https://idp.golden.test'

# Plaintext passwords are synthetic and listed in the manifest.
PASSWORDS = {
    'golden_admin': 'golden-admin-password-1',
    runtime.CONFIG_ADMIN: 'config-admin-password-1',
    'local_user': 'local-user-password-1',
    # 72 bytes in UTF-8, the bcrypt limit the app enforces.
    'limit_user': 'ä' * 30 + 'x' * 12,
    'locked_user': 'locked-user-password-1',
    'totp_user': 'totp-user-password-1',
    'passkey_user': 'passkey-user-password-1',
    'oidc_user': 'oidc-user-password-1',
    'github_linked': 'github-linked-password-1',
}


def _register(username, *, allow_config_admin=False):
    from app.auth import register_user
    user, error = register_user(
        username, PASSWORDS[username], allow_config_admin=allow_config_admin,
    )
    if error:
        raise RuntimeError(f'register_user({username}) failed: {error}')
    return user


def create_local_accounts(clock):
    """Local, admin, ADMIN_USERS-managed, bcrypt-limit and locked accounts."""
    from app.auth import sync_admin_users
    from app.auth_assurance import invalidate_user_authentication
    from app.models import db

    users = {}
    # The first account becomes administrator (app/auth.py register_user).
    users['golden_admin'] = _register('golden_admin')
    clock.advance(seconds=1, microseconds=250000)
    users[runtime.CONFIG_ADMIN] = _register(
        runtime.CONFIG_ADMIN, allow_config_admin=True,
    )
    sync_admin_users()
    for name in ('local_user', 'limit_user', 'locked_user', 'totp_user',
                 'passkey_user', 'oidc_user', 'github_linked'):
        clock.advance(seconds=1)
        users[name] = _register(name)
    # Admin "lock" action (app/__init__.py admin_user_action).
    clock.advance(seconds=1)
    locked = users['locked_user']
    locked.is_locked = True
    invalidate_user_authentication(locked)
    db.session.commit()
    return users


def create_ldap_account(clock):
    """Directory-provisioned account (app/ldap_routes.py, provisioning path)."""
    from app.models import LDAPIdentity, User, db
    import datetime as dt

    clock.advance(seconds=1)
    user = User(username='ldap_user', is_admin=False, is_locked=False)
    user.set_password(secrets.token_urlsafe(48))
    mapping = LDAPIdentity(
        user=user,
        provider='default',
        subject='b64:Z29sZGVuLWxkYXAtZW50cnktdXVpZA',
        directory_username='ldap_user',
        distinguished_name='uid=ldap_user,ou=people,dc=golden,dc=test',
        last_verified_at=dt.datetime.now(dt.timezone.utc),
    )
    db.session.add_all((user, mapping))
    db.session.flush()
    user.get_data_dir()
    db.session.commit()
    return user


def create_github_accounts(clock):
    """GitHub-provisioned account and a GitHub link on a local account."""
    from app.models import GitHubIdentity, User, db
    import datetime as dt

    clock.advance(seconds=1)
    # app/github_auth_routes.py _auto_provision
    user = User(username='octo_golden', is_admin=False)
    user.set_password(secrets.token_urlsafe(48))
    db.session.add(user)
    db.session.flush()
    db.session.add(GitHubIdentity(
        user_id=user.id,
        github_user_id=90000001,
        login='Octo-Golden',
        display_name='Octo Golden',
        provisioned_by_github=True,
        last_verified_at=dt.datetime.now(dt.timezone.utc),
    ))
    db.session.commit()
    user.get_data_dir()

    # app/github_auth_routes.py _complete_link inserts only these columns.
    clock.advance(seconds=1)
    linked = User.query.filter_by(username='github_linked').one()
    db.session.add(GitHubIdentity(
        user_id=linked.id,
        github_user_id=90000002,
        login='linked-golden',
        display_name=None,
        last_verified_at=dt.datetime.now(dt.timezone.utc).replace(tzinfo=None),
    ))
    db.session.commit()
    return user


def create_oidc_identity(clock):
    """Admin OIDC link (app/oidc_routes.py, admin link endpoint)."""
    from app.models import OIDCIdentity, User, db

    clock.advance(seconds=1)
    user = User.query.filter_by(username='oidc_user').one()
    db.session.add(OIDCIdentity(
        user_id=user.id, issuer=OIDC_ISSUER, subject='golden-oidc-subject-1',
    ))
    db.session.commit()


def configure_github(admin_id, clock):
    """Admin GitHub sign-in configuration with an encrypted client secret."""
    from app.github_auth_service import update_settings
    from app.models import db

    clock.advance(seconds=1)
    client_secret = 'golden-github-client-secret-0123456789abcdef'
    update_settings({
        'enabled': False,
        'client_id': 'Iv1-golden0123456789',
        'client_secret': client_secret,
        'redirect_uri': f'{runtime.ORIGIN}/auth/github/callback',
        'auto_provision': False,
        'allowed_orgs': ['golden-org'],
    }, admin_id)
    db.session.commit()
    return client_secret


def activate_security_features(admin_id):
    from app.security_features import set_feature_active
    for name in ('passkey', 'totp', 'recovery'):
        set_feature_active(name, True, admin_id)
