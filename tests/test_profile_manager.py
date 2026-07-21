"""Tests for connection-profile persistence."""


def create_user(app, username='profile-user'):
    from app.models import User, db

    with app.app_context():
        user = User(username=username, password_hash='not-used-in-this-test')
        db.session.add(user)
        db.session.commit()
        return user.id


def test_add_profile_saves_normalized_startup_commands(app):
    from app import profile_manager

    user_id = create_user(app)
    with app.app_context():
        profile, error = profile_manager.add_profile(
            user_id,
            'Production',
            'example.com',
            22,
            'deploy',
            'password',
            startup_commands='echo connected\r\nwhoami',
        )

        assert error is None
        assert profile['startup_commands'] == 'echo connected\nwhoami'
        assert profile_manager.load_profiles(user_id) == [profile]


def test_add_profile_leaves_startup_commands_absent_when_not_provided(app):
    from app import profile_manager

    user_id = create_user(app)
    with app.app_context():
        profile, error = profile_manager.add_profile(
            user_id,
            'Production',
            'example.com',
            22,
            'deploy',
            'password',
        )

        assert error is None
        assert 'startup_commands' not in profile
        assert profile_manager.load_profiles(user_id) == [profile]


def test_load_profiles_preserves_legacy_profiles_without_startup_commands(app):
    from app import profile_manager

    user_id = create_user(app)
    legacy_profile = {
        'id': 'legacy-profile',
        'name': 'Legacy',
        'host': 'example.com',
        'port': 22,
        'username': 'deploy',
        'auth_type': 'password',
    }

    with app.app_context():
        assert profile_manager.save_profiles(user_id, [legacy_profile]) is True
        assert profile_manager.load_profiles(user_id) == [legacy_profile]
