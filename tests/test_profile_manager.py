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


def test_add_profile_saves_command_set_reference_and_keeps_legacy_fallback(app):
    from app import command_set_manager, profile_manager

    user_id = create_user(app, 'profile-command-set')
    with app.app_context():
        command_set, error = command_set_manager.upsert_command_set(user_id, {
            'name': 'Bootstrap',
            'steps': [{'type': 'inline', 'command': 'uptime'}],
        })
        assert error is None

        profile, error = profile_manager.add_profile(
            user_id,
            'Production',
            'example.com',
            22,
            'deploy',
            'password',
            command_set_id=command_set['id'],
            startup_commands='echo legacy',
        )

        assert error is None
        assert profile['command_set_id'] == command_set['id']
        assert profile['startup_commands'] == 'echo legacy'
        assert 'steps' not in profile


def test_add_profile_rejects_unknown_command_set_without_writing(app):
    from app import profile_manager

    user_id = create_user(app, 'profile-missing-command-set')
    with app.app_context():
        profile, error = profile_manager.add_profile(
            user_id,
            'Production',
            'example.com',
            22,
            'deploy',
            'password',
            command_set_id='missing-set',
        )

        assert profile is None
        assert error == 'Command set not found'
        assert profile_manager.load_profiles(user_id) == []


def test_assign_command_set_to_profile_retains_legacy_commands(app):
    from app import command_set_manager, profile_manager

    user_id = create_user(app, 'profile-convert-command-set')
    with app.app_context():
        legacy, error = profile_manager.add_profile(
            user_id,
            'Legacy Production',
            'example.com',
            22,
            'deploy',
            'password',
            startup_commands='echo legacy',
        )
        assert error is None
        command_set, error = command_set_manager.upsert_command_set(user_id, {
            'name': 'Converted',
            'steps': [{'type': 'inline', 'command': 'echo legacy'}],
        })
        assert error is None

        updated, error = profile_manager.assign_command_set(
            user_id, legacy['id'], command_set['id']
        )

        assert error is None
        assert updated['command_set_id'] == command_set['id']
        assert updated['startup_commands'] == 'echo legacy'
