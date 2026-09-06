"""Initial-factor bootstrap codes are narrow, expiring, and one-use."""

from datetime import datetime, timedelta, timezone


def _github_only_user(app, username='bootstrap-user'):
    from app.models import GitHubIdentity, User, db

    with app.app_context():
        user = User(username=username, password_hash='not-a-known-password')
        db.session.add(user)
        db.session.flush()
        db.session.add(GitHubIdentity(
            user_id=user.id,
            github_user_id=f'github-{user.id}',
            login=username,
            provisioned_by_github=True,
        ))
        db.session.commit()
        return user.id


def test_new_bootstrap_code_revokes_previous_and_is_action_bound(app):
    from app.factor_bootstrap import (
        consume_factor_bootstrap,
        has_live_factor_bootstrap,
        issue_factor_bootstrap,
    )
    from app.models import FactorBootstrapToken, User, db

    user_id = _github_only_user(app)
    with app.app_context():
        user = db.session.get(User, user_id)
        first, _expiry = issue_factor_bootstrap(user, 'passkey.enroll')
        second, _expiry = issue_factor_bootstrap(user, 'passkey.enroll')

        assert first != second
        assert FactorBootstrapToken.query.count() == 1
        assert first not in FactorBootstrapToken.query.one().token_hash
        assert has_live_factor_bootstrap(user, 'passkey.enroll') is True
        assert consume_factor_bootstrap(
            user, 'totp.enroll', second
        ) is False
        assert consume_factor_bootstrap(
            user, 'passkey.enroll', first
        ) is False
        assert consume_factor_bootstrap(
            user, 'passkey.enroll', second
        ) is True
        assert consume_factor_bootstrap(
            user, 'passkey.enroll', second
        ) is False


def test_bootstrap_code_expires_at_the_exact_deadline(app):
    from app.factor_bootstrap import (
        consume_factor_bootstrap,
        has_live_factor_bootstrap,
        issue_factor_bootstrap,
    )
    from app.models import User, db

    user_id = _github_only_user(app, 'expiring-bootstrap-user')
    issued_at = datetime.now(timezone.utc)
    with app.app_context():
        user = db.session.get(User, user_id)
        token, expiry = issue_factor_bootstrap(
            user,
            'passkey.enroll',
            now=issued_at,
        )

        assert has_live_factor_bootstrap(
            user,
            'passkey.enroll',
            now=expiry.replace(tzinfo=timezone.utc) - timedelta(microseconds=1),
        ) is True
        assert has_live_factor_bootstrap(
            user,
            'passkey.enroll',
            now=expiry.replace(tzinfo=timezone.utc),
        ) is False
        assert consume_factor_bootstrap(
            user,
            'passkey.enroll',
            token,
            now=expiry.replace(tzinfo=timezone.utc),
        ) is False
