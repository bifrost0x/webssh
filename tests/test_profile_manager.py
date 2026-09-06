"""Tests for connection-profile persistence."""

import pytest
import threading

from app.storage_errors import StorageCorruptionError


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


def test_profile_organization_fields_are_normalized_and_persisted(app):
    from app import profile_manager

    user_id = create_user(app, 'organized-profile')
    with app.app_context():
        profile, error = profile_manager.upsert_profile(user_id, {
            'name': 'Production API',
            'host': 'api.example.com',
            'port': 22,
            'username': 'deploy',
            'auth_type': 'password',
            'group': '  Production  ',
            'favorite': True,
        })

        assert error is None
        assert profile['group'] == 'Production'
        assert profile['favorite'] is True
        assert profile_manager.load_profiles(user_id) == [profile]


def test_profile_tmux_preference_is_validated_and_persisted(app):
    from app import profile_manager

    user_id = create_user(app, 'profile-tmux-preference')
    with app.app_context():
        profile, error = profile_manager.upsert_profile(user_id, {
            'name': 'Persistent shell',
            'host': 'shell.example.com',
            'port': 22,
            'username': 'deploy',
            'auth_type': 'password',
            'use_tmux': True,
        })

        assert error is None
        assert profile['use_tmux'] is True
        assert profile_manager.load_profiles(user_id)[0]['use_tmux'] is True

        profile, error = profile_manager.upsert_profile(user_id, {
            'id': profile['id'],
            'name': 'Persistent shell',
            'host': 'shell.example.com',
            'port': 22,
            'username': 'deploy',
            'auth_type': 'password',
            'use_tmux': False,
        })

        assert error is None
        assert profile['use_tmux'] is False
        assert profile_manager.load_profiles(user_id)[0]['use_tmux'] is False


def test_profile_persistence_strips_response_only_tailscale_authorization(app):
    from app import profile_manager

    user_id = create_user(app, 'tailscale-response-only')
    profile = {
        'id': 'tailscale-profile',
        'name': 'Tailnet server',
        'host': 'tiny-server',
        'port': 22,
        'username': 'root',
        'auth_type': 'tailscale',
        'tailscale_authorized': True,
    }
    with app.app_context():
        assert profile_manager.save_profiles(user_id, [profile]) is True
        stored = profile_manager.load_profiles(user_id)

    assert profile['tailscale_authorized'] is True
    assert stored == [{
        key: value
        for key, value in profile.items()
        if key != 'tailscale_authorized'
    }]


def test_profile_edit_without_tmux_field_preserves_existing_preference(app):
    from app import profile_manager

    user_id = create_user(app, 'profile-tmux-preserve')
    with app.app_context():
        profile, error = profile_manager.upsert_profile(user_id, {
            'name': 'Persistent shell',
            'host': 'shell.example.com',
            'port': 22,
            'username': 'deploy',
            'auth_type': 'password',
            'use_tmux': True,
        })
        assert error is None

        profile, error = profile_manager.upsert_profile(user_id, {
            'id': profile['id'],
            'name': 'Renamed persistent shell',
            'host': 'shell.example.com',
            'port': 22,
            'username': 'deploy',
            'auth_type': 'password',
        })

        assert error is None
        assert profile['use_tmux'] is True
        assert profile_manager.load_profiles(user_id)[0]['use_tmux'] is True


def test_profile_rejects_non_boolean_tmux_preference(app):
    from app import profile_manager

    user_id = create_user(app, 'profile-tmux-invalid')
    with app.app_context():
        profile, error = profile_manager.upsert_profile(user_id, {
            'name': 'Invalid persistent shell',
            'host': 'shell.example.com',
            'port': 22,
            'username': 'deploy',
            'auth_type': 'password',
            'use_tmux': 'true',
        })

        assert profile is None
        assert error == 'use_tmux must be a boolean'
        assert profile_manager.load_profiles(user_id) == []


def test_profile_rejects_tailscale_with_jump_host(app):
    from app import profile_manager

    user_id = create_user(app, 'tailscale-jump-profile')
    with app.app_context():
        profile, error = profile_manager.upsert_profile(user_id, {
            'name': 'Invalid routed target',
            'host': 'server.tailnet.ts.net',
            'port': 22,
            'username': 'deploy',
            'auth_type': 'tailscale',
            'jump_host_id': 'jump-host-1',
        })

        assert profile is None
        assert error == 'Tailscale SSH cannot be used with a jump host'
        assert profile_manager.load_profiles(user_id) == []


@pytest.mark.parametrize('sort_order', [True, -1, '1', 1.5])
def test_profile_document_rejects_invalid_sort_order(app, sort_order):
    from app import profile_manager

    user_id = create_user(app, f'invalid-sort-{str(sort_order).replace(".", "-")}')
    profile = {
        'id': 'profile-1',
        'name': 'API',
        'sort_order': sort_order,
    }

    with app.app_context():
        assert profile_manager.save_profiles(user_id, [profile]) is False


def test_new_profiles_append_to_their_group_and_edits_preserve_position(app):
    from app import profile_manager

    user_id = create_user(app, 'profile-sort-append')
    with app.app_context():
        first, error = profile_manager.upsert_profile(user_id, {
            'name': 'First', 'host': 'first.example.com', 'port': 22,
            'username': 'deploy', 'auth_type': 'password', 'group': 'Production',
        })
        assert error is None
        second, error = profile_manager.upsert_profile(user_id, {
            'name': 'Second', 'host': 'second.example.com', 'port': 22,
            'username': 'deploy', 'auth_type': 'password', 'group': 'Production',
        })
        assert error is None
        other, error = profile_manager.upsert_profile(user_id, {
            'name': 'Other', 'host': 'other.example.com', 'port': 22,
            'username': 'deploy', 'auth_type': 'password', 'group': 'Homelab',
        })
        assert error is None

        assert (first['sort_order'], second['sort_order'], other['sort_order']) == (0, 1, 0)

        edited, error = profile_manager.upsert_profile(user_id, {
            'id': first['id'], 'name': 'First renamed', 'host': 'first.example.com',
            'port': 22, 'username': 'deploy', 'auth_type': 'password',
            'group': 'Production',
        })

        assert error is None
        assert edited['sort_order'] == 0


def test_profile_edit_group_change_appends_to_target_group(app):
    from app import profile_manager

    user_id = create_user(app, 'profile-sort-group-edit')
    with app.app_context():
        source, error = profile_manager.upsert_profile(user_id, {
            'name': 'Source', 'host': 'source.example.com', 'port': 22,
            'username': 'deploy', 'auth_type': 'password', 'group': 'Source',
        })
        assert error is None
        target, error = profile_manager.upsert_profile(user_id, {
            'name': 'Target', 'host': 'target.example.com', 'port': 22,
            'username': 'deploy', 'auth_type': 'password', 'group': 'Target',
        })
        assert error is None

        moved, error = profile_manager.upsert_profile(user_id, {
            'id': source['id'], 'name': 'Source', 'host': 'source.example.com',
            'port': 22, 'username': 'deploy', 'auth_type': 'password',
            'group': 'Target',
        })

        assert error is None
        assert target['sort_order'] == 0
        assert moved['sort_order'] == 1


def test_move_profile_reorders_within_group_and_persists_compact_positions(app):
    from app import profile_manager

    user_id = create_user(app, 'profile-sort-within')
    profiles = [
        {'id': 'one', 'name': 'One', 'group': 'Production', 'sort_order': 0},
        {'id': 'two', 'name': 'Two', 'group': 'Production', 'sort_order': 1},
        {'id': 'three', 'name': 'Three', 'group': 'Production', 'sort_order': 2},
    ]
    with app.app_context():
        assert profile_manager.save_profiles(user_id, profiles) is True

        result, error = profile_manager.move_profile(
            user_id, 'three', 'Production', 'Production', 0,
        )

        assert error is None
        ordered = sorted(result['profiles'], key=lambda item: item['sort_order'])
        assert [item['id'] for item in ordered] == ['three', 'one', 'two']
        assert [item['sort_order'] for item in ordered] == [0, 1, 2]
        assert profile_manager.load_profiles(user_id) == result['profiles']


def test_move_profile_preserves_incomplete_legacy_group_order_before_normalizing(app):
    from app import profile_manager

    user_id = create_user(app, 'profile-sort-legacy-normalize')
    profiles = [
        {'id': 'legacy-first', 'name': 'Legacy first', 'group': 'Target'},
        {'id': 'ordered-second', 'name': 'Ordered second', 'group': 'Target',
         'sort_order': 1},
        {'id': 'legacy-third', 'name': 'Legacy third', 'group': 'Target'},
        {'id': 'move', 'name': 'Move', 'group': 'Source', 'sort_order': 0},
        {'id': 'keep', 'name': 'Keep', 'group': 'Source', 'sort_order': 1},
    ]
    with app.app_context():
        assert profile_manager.save_profiles(user_id, profiles) is True

        result, error = profile_manager.move_profile(
            user_id, 'move', 'Source', 'Target', 3,
        )

        assert error is None
        target = sorted(
            (
                item for item in result['profiles']
                if item.get('group') == 'Target'
            ),
            key=lambda item: item['sort_order'],
        )
        assert [item['id'] for item in target] == [
            'legacy-first', 'ordered-second', 'legacy-third', 'move',
        ]
        assert [item['sort_order'] for item in target] == [0, 1, 2, 3]


def test_move_profile_requires_confirmation_before_removing_last_group_member(app):
    from app import profile_manager

    user_id = create_user(app, 'profile-sort-confirm')
    profiles = [
        {'id': 'source', 'name': 'Critical DB', 'group': 'Databases', 'sort_order': 0},
        {'id': 'target', 'name': 'Worker', 'group': 'Production', 'sort_order': 0},
    ]
    with app.app_context():
        assert profile_manager.save_profiles(user_id, profiles) is True

        result, error = profile_manager.move_profile(
            user_id, 'source', 'Databases', 'Production', 1,
        )

        assert error is None
        assert result == {
            'profiles': profiles,
            'requires_confirmation': True,
            'profile_id': 'source',
            'profile_name': 'Critical DB',
            'source_group': 'Databases',
        }
        assert profile_manager.load_profiles(user_id) == profiles

        result, error = profile_manager.move_profile(
            user_id, 'source', 'Databases', 'Production', 1,
            confirm_source_group_removal=True,
        )

        assert error is None
        assert result['requires_confirmation'] is False
        production = sorted(
            result['profiles'], key=lambda item: item.get('sort_order', 0)
        )
        assert [item['id'] for item in production] == ['target', 'source']
        assert all(item.get('group') == 'Production' for item in production)


def test_move_profile_supports_ungrouped_clamps_index_and_rejects_stale_source(app):
    from app import profile_manager

    user_id = create_user(app, 'profile-sort-stale')
    profiles = [
        {'id': 'move', 'name': 'Move', 'group': 'Production', 'sort_order': 0},
        {'id': 'loose', 'name': 'Loose', 'sort_order': 0},
        {'id': 'keep', 'name': 'Keep', 'group': 'Production', 'sort_order': 1},
    ]
    with app.app_context():
        assert profile_manager.save_profiles(user_id, profiles) is True

        stale, error = profile_manager.move_profile(
            user_id, 'move', 'Homelab', '', 99,
        )
        assert error == 'Profile group changed; retry move'
        assert stale['profiles'] == profiles
        assert profile_manager.load_profiles(user_id) == profiles

        result, error = profile_manager.move_profile(
            user_id, 'move', 'Production', '', 99,
        )

        assert error is None
        ungrouped = sorted(
            [item for item in result['profiles'] if not item.get('group')],
            key=lambda item: item['sort_order'],
        )
        assert [item['id'] for item in ungrouped] == ['loose', 'move']
        assert [item['sort_order'] for item in ungrouped] == [0, 1]


@pytest.mark.parametrize('target_index', [True, -1, '1', 1.5])
def test_move_profile_rejects_invalid_target_index(app, target_index):
    from app import profile_manager

    user_id = create_user(app, f'profile-sort-index-{str(target_index).replace(".", "-")}')
    with app.app_context():
        assert profile_manager.save_profiles(user_id, [
            {'id': 'profile', 'name': 'Profile'},
        ]) is True

        result, error = profile_manager.move_profile(
            user_id, 'profile', '', '', target_index,
        )

        assert result is None
        assert error == 'Invalid target index'


@pytest.mark.parametrize(('field', 'value', 'message'), [
    ('group', {'not': 'a string'}, 'Invalid group'),
    ('group', 'x' * 65, 'Group must not exceed 64 characters'),
    ('favorite', 'true', 'favorite must be a boolean'),
])
def test_profile_organization_rejects_invalid_values(
    app, field, value, message,
):
    from app import profile_manager

    user_id = create_user(app, f'invalid-{field}-{len(str(value))}')
    with app.app_context():
        profile, error = profile_manager.upsert_profile(user_id, {
            'name': 'Host',
            'host': 'host.example.com',
            'port': 22,
            'username': 'deploy',
            'auth_type': 'password',
            field: value,
        })

        assert profile is None
        assert error == message
        assert profile_manager.load_profiles(user_id) == []


def test_profile_edit_preserves_organization_when_fields_are_omitted(app):
    from app import profile_manager

    user_id = create_user(app, 'organization-preserved')
    with app.app_context():
        original, error = profile_manager.upsert_profile(user_id, {
            'name': 'API',
            'host': 'api.example.com',
            'port': 22,
            'username': 'deploy',
            'auth_type': 'password',
            'group': 'Production',
            'favorite': True,
        })
        assert error is None

        updated, error = profile_manager.upsert_profile(user_id, {
            'id': original['id'],
            'name': 'API renamed',
            'host': 'api.example.com',
            'port': 22,
            'username': 'deploy',
            'auth_type': 'password',
        })

        assert error is None
        assert updated['group'] == 'Production'
        assert updated['favorite'] is True


def test_update_profile_organization_changes_only_requested_fields(app):
    from app import profile_manager

    user_id = create_user(app, 'organization-patch')
    with app.app_context():
        original, error = profile_manager.upsert_profile(user_id, {
            'name': 'Database',
            'host': 'db.example.com',
            'port': 2222,
            'username': 'dba',
            'auth_type': 'password',
            'startup_mode': 'free_text',
            'startup_commands': 'uptime',
        })
        assert error is None

        updated, error = profile_manager.update_profile_organization(
            user_id,
            original['id'],
            {'group': 'Databases', 'favorite': True, 'host': 'evil.example'},
        )

        assert error is None
        assert updated['group'] == 'Databases'
        assert updated['favorite'] is True
        assert updated['host'] == 'db.example.com'
        assert updated['startup_commands'] == 'uptime'
        assert updated['updated_at'] >= original['updated_at']
        assert profile_manager.load_profiles(user_id) == [updated]


def test_update_profile_organization_can_clear_optional_fields(app):
    from app import profile_manager

    user_id = create_user(app, 'organization-clear')
    with app.app_context():
        original, error = profile_manager.upsert_profile(user_id, {
            'name': 'Database',
            'host': 'db.example.com',
            'port': 22,
            'username': 'dba',
            'auth_type': 'password',
            'group': 'Databases',
            'favorite': True,
        })
        assert error is None

        updated, error = profile_manager.update_profile_organization(
            user_id, original['id'], {'group': '   ', 'favorite': False}
        )

        assert error is None
        assert 'group' not in updated
        assert 'favorite' not in updated


def test_update_profile_organization_rejects_missing_profile(app):
    from app import profile_manager

    user_id = create_user(app, 'organization-missing')
    with app.app_context():
        updated, error = profile_manager.update_profile_organization(
            user_id, 'foreign-or-missing', {'favorite': True}
        )
        assert updated is None
        assert error == 'Profile not found'


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


def test_add_profile_does_not_overwrite_corrupt_profile_storage(app):
    from app import profile_manager

    user_id = create_user(app, 'profile_corrupt_storage')
    with app.app_context():
        path = profile_manager.get_user_profiles_file(user_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{broken', encoding='utf-8')

        with pytest.raises(StorageCorruptionError) as exc_info:
            profile_manager.add_profile(
                user_id, 'Production', 'example.com', 22, 'deploy', 'password'
            )

        assert exc_info.value.path == path
        assert path.read_text(encoding='utf-8') == '{broken'


def test_upsert_profile_updates_in_place_without_duplicate(app):
    from app import profile_manager

    user_id = create_user(app, 'profile-update')
    with app.app_context():
        created, error = profile_manager.upsert_profile(user_id, {
            'name': 'Production',
            'host': 'old.example.com',
            'port': 22,
            'username': 'deploy',
            'auth_type': 'password',
        })
        updated, update_error = profile_manager.upsert_profile(user_id, {
            'id': created['id'],
            'name': 'Production',
            'host': 'new.example.com',
            'port': 2222,
            'username': 'deploy',
            'auth_type': 'password',
        })
        profiles = profile_manager.load_profiles(user_id)

    assert error is None
    assert update_error is None
    assert updated['id'] == created['id']
    assert updated['created_at'] == created['created_at']
    assert updated['updated_at']
    assert len(profiles) == 1
    assert profiles[0]['host'] == 'new.example.com'
    assert profiles[0]['port'] == 2222


def test_upsert_profile_rejects_unknown_id_without_writing(app):
    from app import profile_manager

    user_id = create_user(app, 'profile-unknown-update')
    with app.app_context():
        profile, error = profile_manager.upsert_profile(user_id, {
            'id': 'not-owned',
            'name': 'Production',
            'host': 'example.com',
            'port': 22,
            'username': 'deploy',
            'auth_type': 'password',
        })

        assert profile is None
        assert error == 'Profile not found'
        assert profile_manager.load_profiles(user_id) == []


def test_delete_profile_rejects_unknown_id_without_writing(app, monkeypatch):
    from app import profile_manager

    user_id = create_user(app, 'profile-unknown-delete')
    with app.app_context():
        monkeypatch.setattr(
            profile_manager,
            'save_profiles',
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError('missing profiles must not be saved')
            ),
        )
        deleted, error = profile_manager.delete_profile(user_id, 'not-owned')

        assert deleted is False
        assert error == 'Profile not found'
        assert profile_manager.load_profiles(user_id) == []


def test_upsert_profile_mode_change_removes_stale_command_fields(app):
    from app import command_set_manager, profile_manager

    user_id = create_user(app, 'profile-mode-change')
    with app.app_context():
        created, error = profile_manager.upsert_profile(user_id, {
            'name': 'Production',
            'host': 'example.com',
            'port': 22,
            'username': 'deploy',
            'auth_type': 'password',
            'startup_mode': 'free_text',
            'startup_commands': 'echo old',
        })
        command_set, set_error = command_set_manager.upsert_command_set(user_id, {
            'name': 'Bootstrap',
            'steps': [{'type': 'inline', 'command': 'uptime'}],
        })
        updated, update_error = profile_manager.upsert_profile(user_id, {
            'id': created['id'],
            'name': 'Production',
            'host': 'example.com',
            'port': 22,
            'username': 'deploy',
            'auth_type': 'password',
            'startup_mode': 'command_set',
            'command_set_id': command_set['id'],
            'startup_commands': 'echo stale fallback',
        })

    assert error is None
    assert set_error is None
    assert update_error is None
    assert updated['startup_mode'] == 'command_set'
    assert updated['command_set_id'] == command_set['id']
    assert 'startup_commands' not in updated
    assert 'command_id' not in updated


def test_upsert_profile_persists_single_command_reference_and_override(
    app, monkeypatch
):
    from app import command_manager, profile_manager

    monkeypatch.setattr(
        command_manager,
        '_get_all_commands_with_lock_held',
        lambda user_id: [{
        'id': 'cmd-echo',
        'name': 'Echo',
        'command': 'echo',
        'parameters': 'default',
    }],
    )
    user_id = create_user(app, 'profile-command')

    with app.app_context():
        profile, error = profile_manager.upsert_profile(user_id, {
            'name': 'Production',
            'host': 'example.com',
            'port': 22,
            'username': 'deploy',
            'auth_type': 'password',
            'startup_mode': 'command',
            'command_id': 'cmd-echo',
            'parameters_override': 'ready',
        })

    assert error is None
    assert profile['startup_mode'] == 'command'
    assert profile['command_id'] == 'cmd-echo'
    assert profile['parameters_override'] == 'ready'
    assert 'startup_commands' not in profile
    assert 'command_set_id' not in profile


def test_upsert_profile_does_not_overwrite_corrupt_storage(app):
    from app import profile_manager

    user_id = create_user(app, 'profile-upsert-corrupt')
    with app.app_context():
        path = profile_manager.get_user_profiles_file(user_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{broken', encoding='utf-8')

        with pytest.raises(StorageCorruptionError) as exc_info:
            profile_manager.upsert_profile(user_id, {
                'name': 'Production',
                'host': 'example.com',
                'port': 22,
                'username': 'deploy',
                'auth_type': 'password',
            })

        assert exc_info.value.path == path
        assert path.read_text(encoding='utf-8') == '{broken'


def test_profile_mutation_acquires_coordinator_before_store_lock(app, monkeypatch):
    """The global-first order prevents profile/command-set ABBA deadlocks."""
    from app import profile_manager
    from app.storage_utils import storage_lock as real_storage_lock

    user_id = create_user(app, 'profile-lock-order')
    first_request = threading.Event()
    requested = []
    result = {}

    def instrumented_storage_lock(key):
        if threading.current_thread().name == 'profile-writer':
            requested.append(key)
            first_request.set()
        return real_storage_lock(key)

    monkeypatch.setattr(
        profile_manager, 'storage_lock', instrumented_storage_lock
    )
    coordinator = real_storage_lock(f'command-config:{user_id}')
    coordinator.acquire()

    def writer():
        with app.app_context():
            result['value'] = profile_manager.upsert_profile(user_id, {
                'name': 'Production',
                'host': 'example.com',
                'port': 22,
                'username': 'deploy',
                'auth_type': 'password',
            })

    thread = threading.Thread(
        target=writer, name='profile-writer', daemon=True
    )
    try:
        thread.start()
        assert first_request.wait(timeout=2)
        assert requested == [f'command-config:{user_id}']

        profile_lock = real_storage_lock(f'profiles:{user_id}')
        assert profile_lock.acquire(blocking=False) is True
        profile_lock.release()
    finally:
        coordinator.release()
        thread.join(timeout=2)

    assert thread.is_alive() is False
    assert result['value'][1] is None


@pytest.mark.parametrize(
    ('mode', 'dependent_store'),
    (('command', 'commands'), ('command_set', 'command-sets')),
)
def test_profile_reference_validation_locks_dependent_store_before_profiles(
    app, monkeypatch, mode, dependent_store
):
    from app import command_manager, command_set_manager, profile_manager
    from app.storage_utils import storage_lock as real_storage_lock

    user_id = create_user(app, f'profile-{mode}-lock-order')
    with app.app_context():
        if mode == 'command':
            reference = command_manager.add_user_command(
                user_id, 'Reference', 'true', '', 'Reference',
                ['all'], 'custom'
            )
        else:
            reference, error = command_set_manager.upsert_command_set(
                user_id,
                {
                    'name': 'Reference',
                    'steps': [{'type': 'inline', 'command': 'true'}],
                },
            )
            assert error is None

    requested = []

    def instrumented_storage_lock(key):
        requested.append(key)
        return real_storage_lock(key)

    monkeypatch.setattr(
        profile_manager, 'storage_lock', instrumented_storage_lock
    )
    with app.app_context():
        profile, error = profile_manager.upsert_profile(
            user_id,
            {
                'name': 'Production',
                'host': 'example.com',
                'port': 22,
                'username': 'deploy',
                'auth_type': 'password',
                'startup_mode': mode,
                f'{mode}_id': reference['id'],
            },
        )

    assert error is None
    assert profile is not None
    assert requested == [
        f'command-config:{user_id}',
        f'{dependent_store}:{user_id}',
        f'profiles:{user_id}',
    ]


def test_assign_command_set_locks_set_snapshot_before_profiles(
    app, monkeypatch
):
    from app import command_set_manager, profile_manager
    from app.storage_utils import storage_lock as real_storage_lock

    user_id = create_user(app, 'assign-set-lock-order')
    with app.app_context():
        profile, error = profile_manager.upsert_profile(
            user_id,
            {
                'name': 'Production',
                'host': 'example.com',
                'port': 22,
                'username': 'deploy',
                'auth_type': 'password',
            },
        )
        assert error is None
        command_set, error = command_set_manager.upsert_command_set(
            user_id,
            {
                'name': 'Bootstrap',
                'steps': [{'type': 'inline', 'command': 'true'}],
            },
        )
        assert error is None

    requested = []

    def instrumented_storage_lock(key):
        requested.append(key)
        return real_storage_lock(key)

    monkeypatch.setattr(
        profile_manager, 'storage_lock', instrumented_storage_lock
    )
    with app.app_context():
        updated, error = profile_manager.assign_command_set(
            user_id, profile['id'], command_set['id']
        )

    assert error is None
    assert updated['command_set_id'] == command_set['id']
    assert requested == [
        f'command-config:{user_id}',
        f'command-sets:{user_id}',
        f'profiles:{user_id}',
    ]


def test_profile_update_preserves_unknown_stored_fields(app):
    from app import profile_manager

    user_id = create_user(app, 'profile-preserve-unknown')
    with app.app_context():
        original = {
            'id': 'profile-1',
            'name': 'Original',
            'future': {'version': 2},
        }
        assert profile_manager.save_profiles(user_id, [original]) is True

        updated, error = profile_manager.upsert_profile(
            user_id,
            {
                'id': 'profile-1',
                'name': 'Updated',
                'host': 'example.com',
                'port': 22,
                'username': 'deploy',
                'auth_type': 'password',
            },
        )

    assert error is None
    assert updated['future'] == {'version': 2}


def test_profile_count_quota_is_atomic_and_delete_remains_available(
    app,
    monkeypatch,
):
    import config
    from app import profile_manager

    user_id = create_user(app, 'profile-count-quota')
    monkeypatch.setattr(config, 'PROFILE_MAX_RECORDS', 1)
    payload = {
        'name': 'First',
        'host': 'example.com',
        'port': 22,
        'username': 'deploy',
        'auth_type': 'password',
    }
    with app.app_context():
        first, error = profile_manager.upsert_profile(user_id, payload)
        assert error is None

        second, error = profile_manager.upsert_profile(
            user_id, {**payload, 'name': 'Second'}
        )

        assert second is None
        assert error.startswith('Connection storage quota exceeded:')
        assert profile_manager.load_profiles(user_id) == [first]
        assert profile_manager.delete_profile(user_id, first['id']) == (
            True, None
        )


def test_profile_cannot_reference_another_users_ssh_key(
    app,
    rsa_private_key_pem,
):
    from app import key_manager, profile_manager

    owner_id = create_user(app, 'profile-key-owner')
    attacker_id = create_user(app, 'profile-key-attacker')
    with app.app_context():
        key, error = key_manager.save_key(
            owner_id, 'Owner key', rsa_private_key_pem
        )
        assert error is None

        profile, error = profile_manager.upsert_profile(attacker_id, {
            'name': 'Foreign key',
            'host': 'example.com',
            'port': 22,
            'username': 'deploy',
            'auth_type': 'key',
            'key_id': key['id'],
        })

    assert profile is None
    assert error == 'SSH key not found'


def test_legacy_oversized_profile_store_has_bounded_offline_recovery(
    app,
    monkeypatch,
):
    import json
    import config
    from app import command_set_manager, profile_manager
    from app.connection_storage_policy import ConnectionStorageLimitError
    from app.storage_migrations import CURRENT_STORAGE_VERSIONS

    user_id = create_user(app, 'oversized-profile-recovery')
    profile = {
        'id': 'legacy-large',
        'name': 'Legacy',
        'future': 'x' * 1024,
    }
    with app.app_context():
        command_set, error = command_set_manager.upsert_command_set(user_id, {
            'name': 'Recovery guard',
            'steps': [{'type': 'inline', 'command': 'true'}],
        })
        assert error is None
        path = profile_manager.get_user_profiles_file(user_id)
        path.write_text(json.dumps({
            'schema_version': CURRENT_STORAGE_VERSIONS['profiles'],
            'profiles': [profile],
        }), encoding='utf-8')
        monkeypatch.setattr(config, 'CONNECTION_STORE_MAX_BYTES', 256)

        with pytest.raises(ConnectionStorageLimitError):
            profile_manager.load_profiles(user_id)
        summaries, summary_error = (
            profile_manager.load_profile_recovery_summaries(user_id)
        )
        assert summary_error is None
        assert summaries == [{
            'id': 'legacy-large',
            'name': 'Legacy',
            'host': '',
            'selector': summaries[0]['selector'],
        }]
        expected = (
            'Connection storage quota exceeded: stored data exceeds its byte limit'
        )
        assert profile_manager.upsert_profile(user_id, {
            'name': 'New',
            'host': 'example.com',
            'port': 22,
            'username': 'deploy',
            'auth_type': 'password',
        }) == (None, expected)
        assert profile_manager.update_profile_organization(
            user_id, profile['id'], {'favorite': True}
        ) == (None, expected)
        assert profile_manager.move_profile(
            user_id, profile['id'], '', 'Production', 0
        ) == (None, expected)
        assert profile_manager.assign_command_set(
            user_id, profile['id'], command_set['id']
        ) == (None, expected)
        assert profile_manager.delete_profile(
            user_id, profile['id']
        ) == (False, expected)
        assert profile_manager.delete_profile_recovery_record(
            user_id, summaries[0]['selector']
        ) == (True, None)
        assert profile_manager.load_profiles(user_id) == []


def test_normal_profile_delete_removes_only_first_duplicate_id(app):
    from app import profile_manager

    user_id = create_user(app, 'duplicate-profile-delete')
    with app.app_context():
        assert profile_manager.save_profiles(user_id, [
            {'id': 'duplicate-id', 'name': 'First'},
            {'id': 'duplicate-id', 'name': 'Second'},
        ])

        assert profile_manager.delete_profile(
            user_id,
            'duplicate-id',
        ) == (True, None)

        assert profile_manager.load_profiles(user_id) == [
            {'id': 'duplicate-id', 'name': 'Second'},
        ]


def test_normal_profile_delete_from_compact_limit_store_stays_readable(
    app,
    monkeypatch,
):
    import json
    import config
    from app import profile_manager
    from app.storage_migrations import CURRENT_STORAGE_VERSIONS

    user_id = create_user(app, 'compact-profile-delete')
    profiles = [
        {'id': str(index), 'name': 'x'}
        for index in range(50)
    ]
    document = {
        'schema_version': CURRENT_STORAGE_VERSIONS['profiles'],
        'profiles': profiles,
    }
    original = json.dumps(document, separators=(',', ':')).encode('utf-8')

    with app.app_context():
        path = profile_manager.get_user_profiles_file(user_id)
        path.write_bytes(original)
        monkeypatch.setattr(
            config,
            'CONNECTION_STORE_MAX_BYTES',
            len(original),
        )
        monkeypatch.setattr(
            config,
            'CONNECTION_CONFIG_MAX_BYTES',
            len(original),
        )

        assert profile_manager.delete_profile(
            user_id,
            profiles[-1]['id'],
        ) == (True, None)

        expected = json.dumps({
            **document,
            'profiles': profiles[:-1],
        }, separators=(',', ':')).encode('utf-8')
        assert path.read_bytes() == expected
        assert len(expected) < len(original)
        assert profile_manager.load_profiles(user_id) == profiles[:-1]


def test_profile_shrink_uses_compact_fallback_at_combined_cap(
    app,
    monkeypatch,
):
    import json
    import config
    from app import profile_manager
    from app.storage_migrations import CURRENT_STORAGE_VERSIONS

    user_id = create_user(app, 'compact-profile-update')
    profiles = [
        {
            'id': f'profile-{index}',
            'name': 'x' * 128,
            'host': 'example.com',
            'port': 22,
            'username': 'deploy',
            'auth_type': 'password',
            'key_id': None,
            'startup_mode': 'none',
            'created_at': '2026-01-01T00:00:00.000000+00:00',
            'updated_at': '2026-01-01T00:00:00.000000+00:00',
            'sort_order': index,
        }
        for index in range(20)
    ]
    profile = profiles[0]
    document = {
        'schema_version': CURRENT_STORAGE_VERSIONS['profiles'],
        'profiles': profiles,
    }
    original = json.dumps(document, separators=(',', ':')).encode('utf-8')
    jump_document = {
        'schema_version': CURRENT_STORAGE_VERSIONS['jump_hosts'],
        'jump_hosts': [],
    }
    jump_bytes = json.dumps(
        jump_document,
        separators=(',', ':'),
    ).encode('utf-8')

    with app.app_context():
        path = profile_manager.get_user_profiles_file(user_id)
        path.write_bytes(original)
        (path.parent / 'jump_hosts.json').write_bytes(jump_bytes)
        monkeypatch.setattr(config, 'CONNECTION_STORE_MAX_BYTES', 100_000)
        monkeypatch.setattr(
            config,
            'CONNECTION_CONFIG_MAX_BYTES',
            len(original) + len(jump_bytes),
        )

        updated, error = profile_manager.upsert_profile(user_id, {
            'id': profile['id'],
            'name': 'Short',
            'host': profile['host'],
            'port': profile['port'],
            'username': profile['username'],
            'auth_type': profile['auth_type'],
        })

        assert error is None
        assert updated['name'] == 'Short'
        persisted = path.read_bytes()
        persisted_document = json.loads(persisted.decode('utf-8'))
        assert persisted == json.dumps(
            persisted_document,
            separators=(',', ':'),
        ).encode('utf-8')
        assert len(persisted) < len(original)
        assert len(persisted) + len(jump_bytes) <= (
            config.CONNECTION_CONFIG_MAX_BYTES
        )
        reloaded = profile_manager.load_profiles(user_id)
        assert reloaded[0] == updated
        assert [item['id'] for item in reloaded[1:]] == [
            item['id'] for item in profiles[1:]
        ]


def test_profile_recovery_ceiling_rejects_before_json_load(app, monkeypatch):
    import config
    from app import profile_manager
    from app.connection_storage_policy import ConnectionStorageLimitError

    user_id = create_user(app, 'profile-recovery-hard-limit')
    with app.app_context():
        path = profile_manager.get_user_profiles_file(user_id)
        path.write_bytes(b'x' * 257)
        monkeypatch.setattr(config, 'CONNECTION_STORE_RECOVERY_MAX_BYTES', 256)
        monkeypatch.setattr(
            profile_manager,
            'load_json_migrated',
            lambda *_args, **_kwargs: pytest.fail(
                'oversized recovery store was parsed'
            ),
        )

        with pytest.raises(ConnectionStorageLimitError):
            profile_manager.load_profile_recovery_summaries(user_id)

        deleted, error = profile_manager.delete_profile_recovery_record(
            user_id,
            'r1:0:' + ('0' * 64),
        )

    assert deleted is False
    assert error == (
        'Connection storage quota exceeded: stored data exceeds its recovery '
        'byte limit'
    )


def test_profile_recovery_record_ceiling_rejects_after_bounded_load(
    app,
    monkeypatch,
):
    import json
    import config
    from app import profile_manager, storage_migrations

    user_id = create_user(app, 'profile-recovery-record-limit')
    document = {
        'schema_version': 1,
        'profiles': [
            {'id': 'target', 'name': 'Target'},
            {'id': 'other', 'name': 'Other'},
        ],
    }
    with app.app_context():
        path = profile_manager.get_user_profiles_file(user_id)
        original = json.dumps(document, separators=(',', ':')).encode('utf-8')
        path.write_bytes(original)
        monkeypatch.setattr(
            config,
            'CONNECTION_STORE_RECOVERY_MAX_RECORDS',
            1,
        )
        monkeypatch.setattr(
            storage_migrations,
            'migrate_document',
            lambda *_args: pytest.fail('over-record store was migrated'),
        )

        deleted, error = profile_manager.delete_profile_recovery_record(
            user_id,
            'r1:0:' + ('0' * 64),
        )

        assert path.read_bytes() == original
        assert list(path.parent.glob('profiles.json.*.bak')) == []

    assert deleted is False
    assert error == (
        'Connection storage quota exceeded: more than 1 recovery records '
        'are not allowed'
    )


def test_profile_recovery_delete_persists_valid_legacy_shrink(
    app,
    monkeypatch,
):
    import json
    import config
    from app import profile_manager
    from app.storage_migrations import CURRENT_STORAGE_VERSIONS

    user_id = create_user(app, 'profile-recovery-legacy-shrink')
    with app.app_context():
        path = profile_manager.get_user_profiles_file(user_id)
        original = json.dumps({
            'schema_version': 1,
            'profiles': [
                {'id': 'target', 'name': 'Target'},
                {'id': 'other', 'name': 'Other'},
            ],
        }, separators=(',', ':')).encode('utf-8')
        path.write_bytes(original)
        monkeypatch.setattr(
            config,
            'CONNECTION_STORE_MAX_BYTES',
            len(original) - 1,
        )
        monkeypatch.setattr(
            config,
            'CONNECTION_CONFIG_MAX_BYTES',
            len(original) - 1,
        )
        monkeypatch.setattr(
            config,
            'CONNECTION_STORE_RECOVERY_MAX_BYTES',
            4096,
        )

        summaries, error = profile_manager.load_profile_recovery_summaries(
            user_id
        )
        assert error is None
        selector = next(
            item['selector'] for item in summaries if item['id'] == 'target'
        )
        assert profile_manager.delete_profile_recovery_record(
            user_id,
            selector,
        ) == (True, None)

        document = json.loads(path.read_text(encoding='utf-8'))
        assert document['schema_version'] == CURRENT_STORAGE_VERSIONS['profiles']
        assert [item['id'] for item in document['profiles']] == ['other']
        assert path.read_bytes() == json.dumps(
            document,
            separators=(',', ':'),
        ).encode('utf-8')
        assert path.stat().st_size < len(original)


def test_profile_recovery_delete_compacts_exact_hard_cap_store(
    app,
    monkeypatch,
):
    import json
    import config
    from app import profile_manager
    from app.storage_migrations import CURRENT_STORAGE_VERSIONS

    user_id = create_user(app, 'profile-recovery-compact-cap')
    profiles = [
        {'id': str(index), 'name': 'x'}
        for index in range(50)
    ]
    document = {
        'schema_version': CURRENT_STORAGE_VERSIONS['profiles'],
        'profiles': profiles,
    }
    original = json.dumps(document, separators=(',', ':')).encode('utf-8')
    assert len(original) == 1173

    with app.app_context():
        path = profile_manager.get_user_profiles_file(user_id)
        path.write_bytes(original)
        monkeypatch.setattr(config, 'CONNECTION_STORE_MAX_BYTES', 64)
        monkeypatch.setattr(config, 'CONNECTION_CONFIG_MAX_BYTES', 64)
        monkeypatch.setattr(
            config,
            'CONNECTION_STORE_RECOVERY_MAX_BYTES',
            len(original),
        )

        summaries, error = profile_manager.load_profile_recovery_summaries(
            user_id
        )
        assert error is None
        assert profile_manager.delete_profile_recovery_record(
            user_id,
            summaries[-1]['selector'],
        ) == (True, None)

        expected = json.dumps({
            'schema_version': CURRENT_STORAGE_VERSIONS['profiles'],
            'profiles': profiles[:-1],
        }, separators=(',', ':')).encode('utf-8')
        assert path.read_bytes() == expected
        assert len(expected) < len(original)


def test_profile_recovery_delete_never_grows_migrated_store(
    app,
    monkeypatch,
):
    import json
    import config
    from app import profile_manager

    user_id = create_user(app, 'profile-recovery-migration-no-growth')
    document = {
        'schema_version': 1,
        'profiles': [
            {'id': str(index), 'name': 'x'}
            for index in range(3)
        ],
    }
    original = json.dumps(document, separators=(',', ':')).encode('utf-8')
    assert len(original) == 99

    with app.app_context():
        path = profile_manager.get_user_profiles_file(user_id)
        path.write_bytes(original)
        monkeypatch.setattr(
            config,
            'CONNECTION_STORE_MAX_BYTES',
            len(original) - 1,
        )
        monkeypatch.setattr(
            config,
            'CONNECTION_CONFIG_MAX_BYTES',
            len(original) - 1,
        )
        monkeypatch.setattr(
            config,
            'CONNECTION_STORE_RECOVERY_MAX_BYTES',
            4096,
        )
        summaries, error = profile_manager.load_profile_recovery_summaries(
            user_id
        )
        assert error is None

        deleted, error = profile_manager.delete_profile_recovery_record(
            user_id,
            summaries[-1]['selector'],
        )

        assert deleted is False
        assert error == (
            'Connection storage quota exceeded: recovery deletion would grow '
            'its connection store'
        )
        assert path.read_bytes() == original


def test_normal_profile_save_keeps_pretty_json(app):
    import json
    from app import profile_manager
    from app.storage_migrations import CURRENT_STORAGE_VERSIONS

    user_id = create_user(app, 'profile-normal-pretty-json')
    profiles = [{'id': 'profile-1', 'name': 'Production'}]
    with app.app_context():
        path = profile_manager.get_user_profiles_file(user_id)
        assert profile_manager.save_profiles(user_id, profiles) is True

        assert path.read_bytes() == json.dumps({
            'schema_version': CURRENT_STORAGE_VERSIONS['profiles'],
            'profiles': profiles,
        }, indent=2).encode('utf-8')
