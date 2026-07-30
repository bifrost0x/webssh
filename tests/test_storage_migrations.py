import hashlib
import json
import os
from pathlib import Path
import stat
import threading
from unittest.mock import Mock

import pytest

from app.storage_migrations import (
    CURRENT_STORAGE_VERSIONS,
    backup_before_migration,
    migrate_document,
    migrate_file,
)
from app.storage_errors import StorageCorruptionError


STORE_DOCUMENTS = {
    'profiles': {'profiles': []},
    'commands': [],
    'command_sets': {'command_sets': []},
    'jump_hosts': {'jump_hosts': []},
    'keys': {'keys': []},
    'settings': {'theme': 'glass'},
    'app_settings': {'registration_enabled': True},
}


@pytest.mark.parametrize(('store_name', 'legacy'), STORE_DOCUMENTS.items())
def test_each_legacy_store_migrates_sequentially_and_idempotently(
    store_name, legacy
):
    migrated, changed = migrate_document(store_name, legacy)
    again, changed_again = migrate_document(store_name, migrated)

    assert changed is True
    assert changed_again is False
    assert migrated['schema_version'] == CURRENT_STORAGE_VERSIONS[store_name]
    assert again == migrated


def test_migration_is_idempotent_and_preserves_unknown_fields():
    source = {
        'schema_version': 1,
        'items': [],
        'future_field': {'keep': True},
    }
    first, changed = migrate_document('jump_hosts', source)
    second, changed_again = migrate_document('jump_hosts', first)

    assert changed is True
    assert changed_again is False
    assert second == first
    assert second['future_field'] == {'keep': True}


def test_commands_legacy_list_becomes_versioned_wrapper_without_api_data_loss():
    source = [{'id': 'command-1', 'name': 'One', 'command': 'whoami'}]

    migrated, changed = migrate_document('commands', source)

    assert changed is True
    assert migrated['commands'] == source


def test_profiles_preserve_legacy_and_explicit_post_connect_semantics():
    profiles = [
        {'id': 'free', 'name': 'Free', 'startup_commands': 'pwd'},
        {
            'id': 'explicit-none',
            'name': 'None',
            'startup_mode': 'none',
            'startup_commands': 'legacy fallback',
            'command_id': 'keep-command',
            'command_set_id': 'keep-set',
            'parameters_override': '',
        },
        {
            'id': 'absent-override',
            'name': 'Command',
            'command_id': 'command-1',
        },
    ]

    migrated, _changed = migrate_document('profiles', {'profiles': profiles})
    by_id = {item['id']: item for item in migrated['profiles']}

    assert by_id['free']['startup_mode'] == 'free_text'
    assert by_id['free']['startup_commands'] == 'pwd'
    assert by_id['explicit-none'] == {
        **profiles[1],
        'startup_mode': 'none',
    }
    assert 'parameters_override' not in by_id['absent-override']
    assert by_id['absent-override']['command_id'] == 'command-1'
    assert by_id['absent-override']['startup_mode'] == 'command'


def test_future_versions_and_unknown_stores_are_rejected():
    with pytest.raises(ValueError, match='future storage version'):
        migrate_document(
            'profiles',
            {'schema_version': CURRENT_STORAGE_VERSIONS['profiles'] + 1},
        )
    with pytest.raises(ValueError, match='unknown storage store'):
        migrate_document('missing', {})


def test_backup_copies_exact_bytes_with_unique_name_and_private_mode(tmp_path):
    path = tmp_path / 'profiles.json'
    source = b'{"profiles":[]}\r\n'
    path.write_bytes(source)

    first = backup_before_migration(path)
    second = backup_before_migration(path)

    assert first != second
    assert first.parent == path.parent
    assert first.read_bytes() == source
    assert second.read_bytes() == source
    assert hashlib.sha256(first.read_bytes()).digest() == hashlib.sha256(source).digest()
    if os.name != 'nt':
        assert stat.S_IMODE(first.stat().st_mode) == 0o600


def test_backup_syncs_parent_directory_after_verified_file_creation(
    tmp_path, monkeypatch
):
    from app import storage_migrations

    path = tmp_path / 'profiles.json'
    source = b'{"profiles":[]}'
    path.write_bytes(source)
    calls = []

    def record_directory_fsync(target):
        backup = next(tmp_path.glob('profiles.json.*.bak'))
        assert backup.read_bytes() == source
        assert Path(target) == backup
        calls.append('directory_fsync')

    monkeypatch.setattr(
        storage_migrations,
        'fsync_parent_directory',
        record_directory_fsync,
        raising=False,
    )

    backup = backup_before_migration(path)

    assert calls == ['directory_fsync']
    assert backup.read_bytes() == source


def test_backup_directory_fsync_failure_stops_before_active_replace(
    tmp_path, monkeypatch
):
    from app import storage_migrations

    path = tmp_path / 'jump_hosts.json'
    source = b'{"jump_hosts":[]}'
    path.write_bytes(source)
    write = Mock(side_effect=AssertionError('active replace must not run'))
    monkeypatch.setattr(
        storage_migrations,
        'fsync_parent_directory',
        Mock(side_effect=OSError('backup directory sync failed')),
        raising=False,
    )
    monkeypatch.setattr(storage_migrations, 'atomic_write_json', write)

    with pytest.raises(OSError, match='backup directory sync failed'):
        migrate_file(path, 'jump_hosts')

    assert path.read_bytes() == source
    assert list(tmp_path.glob('jump_hosts.json.*.bak')) == []
    write.assert_not_called()


def test_migrate_file_keeps_original_active_when_replace_fails_after_backup(
    tmp_path, monkeypatch
):
    path = tmp_path / 'jump_hosts.json'
    source = b'{"jump_hosts":[]}'
    path.write_bytes(source)

    from app import storage_migrations

    monkeypatch.setattr(
        storage_migrations,
        'atomic_write_json',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError('blocked')),
    )
    with pytest.raises(OSError, match='blocked'):
        migrate_file(path, 'jump_hosts')

    assert path.read_bytes() == source
    backups = list(tmp_path.glob('jump_hosts.json.*.bak'))
    assert len(backups) == 1
    assert backups[0].read_bytes() == source


def test_migrate_file_does_not_write_or_backup_current_document(
    tmp_path, monkeypatch
):
    path = tmp_path / 'settings.json'
    current, _ = migrate_document('settings', {'theme': 'glass'})
    payload = json.dumps(current, indent=2).encode('utf-8')
    path.write_bytes(payload)

    from app import storage_migrations

    monkeypatch.setattr(
        storage_migrations,
        'backup_before_migration',
        lambda *_args: (_ for _ in ()).throw(AssertionError('backup called')),
    )
    monkeypatch.setattr(
        storage_migrations,
        'atomic_write_json',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError('write called')),
    )

    result = migrate_file(path, 'settings')

    assert result == current
    assert path.read_bytes() == payload


def test_backup_failure_fails_closed_without_touching_original(
    tmp_path, monkeypatch
):
    path = tmp_path / 'profiles.json'
    source = b'{"profiles":[]}'
    path.write_bytes(source)

    from app import storage_migrations

    monkeypatch.setattr(
        storage_migrations,
        'backup_before_migration',
        lambda *_args: (_ for _ in ()).throw(OSError('backup blocked')),
    )
    with pytest.raises(OSError, match='backup blocked'):
        migrate_file(path, 'profiles')

    assert path.read_bytes() == source
    assert list(tmp_path.glob('profiles.json.*.bak')) == []


def test_corrupt_storage_is_left_untouched(tmp_path):
    path = tmp_path / 'profiles.json'
    source = b'{broken'
    path.write_bytes(source)

    with pytest.raises(StorageCorruptionError) as exc_info:
        migrate_file(path, 'profiles')

    assert exc_info.value.reason == 'invalid JSON'
    assert path.read_bytes() == source
    assert list(tmp_path.glob('profiles.json.*.bak')) == []


def _create_user(app, username):
    from app.models import User, db

    user = User(username=username)
    user.set_password('migration-test-password')
    db.session.add(user)
    db.session.commit()
    return user.id


@pytest.mark.parametrize(
    ('store_name', 'relative_path', 'legacy', 'loader'),
    [
        (
            'profiles',
            'profiles.json',
            {'profiles': []},
            lambda uid: __import__(
                'app.profile_manager', fromlist=['load_profiles']
            ).load_profiles(uid),
        ),
        (
            'commands',
            'commands.json',
            [],
            lambda uid: __import__(
                'app.command_manager', fromlist=['load_user_commands']
            ).load_user_commands(uid),
        ),
        (
            'command_sets',
            'command_sets.json',
            {'command_sets': []},
            lambda uid: __import__(
                'app.command_set_manager', fromlist=['load_command_sets']
            ).load_command_sets(uid)[0],
        ),
        (
            'jump_hosts',
            'jump_hosts.json',
            {'jump_hosts': []},
            lambda uid: __import__(
                'app.jump_host_manager', fromlist=['load_jump_hosts']
            ).load_jump_hosts(uid),
        ),
        (
            'keys',
            'keys/keys.json',
            {'keys': []},
            lambda uid: __import__(
                'app.key_manager', fromlist=['load_keys']
            ).load_keys(uid),
        ),
        (
            'settings',
            'settings.json',
            {'theme': 'glass'},
            lambda uid: __import__(
                'app.user_settings', fromlist=['get_user_settings']
            ).get_user_settings(uid),
        ),
    ],
)
def test_manager_load_migrates_legacy_once_under_its_store_lock(
    app, store_name, relative_path, legacy, loader
):
    from app.models import User, db

    with app.app_context():
        user_id = _create_user(app, f'migration-{store_name}')
        path = db.session.get(User, user_id).get_data_dir() / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        original = json.dumps(legacy, separators=(',', ':')).encode('utf-8')
        path.write_bytes(original)

        loader(user_id)
        first_bytes = path.read_bytes()
        loader(user_id)

        document = json.loads(first_bytes)
        assert document['schema_version'] == CURRENT_STORAGE_VERSIONS[store_name]
        assert path.read_bytes() == first_bytes
        backups = list(path.parent.glob(f'{path.name}.*.bak'))
        assert len(backups) == 1
        assert backups[0].read_bytes() == original


def test_manager_rejects_future_version_without_backup_or_write(app):
    from app import profile_manager
    from app.models import User, db

    with app.app_context():
        user_id = _create_user(app, 'migration-future')
        path = db.session.get(User, user_id).get_data_dir() / 'profiles.json'
        source = json.dumps({
            'schema_version': CURRENT_STORAGE_VERSIONS['profiles'] + 1,
            'profiles': [],
        }).encode('utf-8')
        path.write_bytes(source)

        with pytest.raises(StorageCorruptionError) as exc_info:
            profile_manager.load_profiles(user_id)

        assert exc_info.value.reason == 'unsupported schema'
        assert path.read_bytes() == source
        assert list(path.parent.glob('profiles.json.*.bak')) == []


@pytest.mark.parametrize(
    ('store_name', 'relative_path', 'document', 'loader'),
    [
        (
            'profiles',
            'profiles.json',
            {'profiles': []},
            lambda uid: __import__(
                'app.profile_manager', fromlist=['load_profiles']
            ).load_profiles(uid),
        ),
        (
            'commands',
            'commands.json',
            {'commands': []},
            lambda uid: __import__(
                'app.command_manager', fromlist=['load_user_commands']
            ).load_user_commands(uid),
        ),
        (
            'command_sets',
            'command_sets.json',
            {'command_sets': []},
            lambda uid: __import__(
                'app.command_set_manager', fromlist=['load_command_sets']
            ).load_command_sets(uid),
        ),
        (
            'jump_hosts',
            'jump_hosts.json',
            {'jump_hosts': []},
            lambda uid: __import__(
                'app.jump_host_manager', fromlist=['load_jump_hosts']
            ).load_jump_hosts(uid),
        ),
        (
            'keys',
            'keys/keys.json',
            {'keys': []},
            lambda uid: __import__(
                'app.key_manager', fromlist=['load_keys']
            ).load_keys(uid),
        ),
        (
            'settings',
            'settings.json',
            {'theme': 'glass'},
            lambda uid: __import__(
                'app.user_settings', fromlist=['get_user_settings']
            ).get_user_settings(uid),
        ),
    ],
)
def test_each_manager_rejects_future_version_without_touching_source(
    app, store_name, relative_path, document, loader
):
    from app.models import User, db

    with app.app_context():
        user_id = _create_user(app, f'migration-future-{store_name}')
        path = db.session.get(User, user_id).get_data_dir() / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        source = json.dumps({
            **document,
            'schema_version': CURRENT_STORAGE_VERSIONS[store_name] + 1,
        }, separators=(',', ':')).encode('utf-8')
        path.write_bytes(source)

        with pytest.raises(StorageCorruptionError) as exc_info:
            loader(user_id)

        assert exc_info.value.reason == 'unsupported schema'
        assert path.read_bytes() == source
        assert list(path.parent.glob(f'{path.name}.*.bak')) == []


@pytest.mark.parametrize(
    ('relative_path', 'loader'),
    [
        (
            'profiles.json',
            lambda uid: __import__(
                'app.profile_manager', fromlist=['load_profiles']
            ).load_profiles(uid),
        ),
        (
            'commands.json',
            lambda uid: __import__(
                'app.command_manager', fromlist=['load_user_commands']
            ).load_user_commands(uid),
        ),
        (
            'command_sets.json',
            lambda uid: __import__(
                'app.command_set_manager', fromlist=['load_command_sets']
            ).load_command_sets(uid),
        ),
        (
            'jump_hosts.json',
            lambda uid: __import__(
                'app.jump_host_manager', fromlist=['load_jump_hosts']
            ).load_jump_hosts(uid),
        ),
        (
            'keys/keys.json',
            lambda uid: __import__(
                'app.key_manager', fromlist=['load_keys']
            ).load_keys(uid),
        ),
        (
            'settings.json',
            lambda uid: __import__(
                'app.user_settings', fromlist=['get_user_settings']
            ).get_user_settings(uid),
        ),
    ],
)
def test_each_manager_leaves_corrupt_source_untouched(
    app, relative_path, loader
):
    from app.models import User, db

    with app.app_context():
        username = relative_path.replace('/', '-').replace('.', '-')
        user_id = _create_user(app, f'migration-corrupt-{username}')
        path = db.session.get(User, user_id).get_data_dir() / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        source = b'{broken'
        path.write_bytes(source)

        with pytest.raises(StorageCorruptionError) as exc_info:
            loader(user_id)

        assert exc_info.value.reason == 'invalid JSON'
        assert path.read_bytes() == source
        assert list(path.parent.glob(f'{path.name}.*.bak')) == []


def test_commands_manager_keeps_list_api_while_migrating_disk_wrapper_once(app):
    from app import command_manager
    from app.models import User, db

    command = {
        'id': 'legacy-command',
        'name': 'Legacy',
        'command': 'whoami',
        'parameters': '',
        'description': '',
        'os': ['all'],
        'category': 'custom',
        'createdAt': '2026-07-24T00:00:00',
    }

    with app.app_context():
        user_id = _create_user(app, 'migration-command-wrapper')
        path = db.session.get(User, user_id).get_data_dir() / 'commands.json'
        source = json.dumps([command], separators=(',', ':')).encode('utf-8')
        path.write_bytes(source)

        first = command_manager.load_user_commands(user_id)
        migrated_bytes = path.read_bytes()
        second = command_manager.load_user_commands(user_id)

        assert first == [command]
        assert second == [command]
        assert json.loads(migrated_bytes) == {
            'schema_version': CURRENT_STORAGE_VERSIONS['commands'],
            'commands': [command],
        }
        assert path.read_bytes() == migrated_bytes
        backups = list(path.parent.glob('commands.json.*.bak'))
        assert len(backups) == 1
        assert backups[0].read_bytes() == source


def test_app_settings_loader_migrates_once(monkeypatch, tmp_path):
    from app import app_settings

    path = tmp_path / 'app_settings.json'
    original = b'{"registration_enabled":false}'
    path.write_bytes(original)
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', path)

    assert app_settings.is_registration_enabled() is False
    first_bytes = path.read_bytes()
    assert app_settings.is_registration_enabled() is False

    assert json.loads(first_bytes)['schema_version'] == (
        CURRENT_STORAGE_VERSIONS['app_settings']
    )
    assert path.read_bytes() == first_bytes
    backups = list(tmp_path.glob('app_settings.json.*.bak'))
    assert len(backups) == 1
    assert backups[0].read_bytes() == original


@pytest.mark.parametrize('source', [
    b'{broken',
    json.dumps({
        'schema_version': CURRENT_STORAGE_VERSIONS['app_settings'] + 1,
        'registration_enabled': False,
    }).encode('utf-8'),
])
def test_app_settings_rejects_unreadable_versions_without_touching_source(
    monkeypatch, tmp_path, source
):
    from app import app_settings

    path = tmp_path / 'app_settings.json'
    path.write_bytes(source)
    monkeypatch.setattr(app_settings, '_SETTINGS_FILE', path)

    with pytest.raises(StorageCorruptionError):
        app_settings.is_registration_enabled()

    assert path.read_bytes() == source
    assert list(tmp_path.glob('app_settings.json.*.bak')) == []


@pytest.mark.parametrize('mode', ['command', 'command_set'])
def test_profile_reference_validation_completes_without_reentrant_store_lock(
    app, mode
):
    from app import command_manager, command_set_manager, profile_manager

    with app.app_context():
        user_id = _create_user(app, f'migration-lock-{mode}')
        if mode == 'command':
            reference = command_manager.add_user_command(
                user_id, 'Reference', 'true', '', 'Reference',
                ['all'], 'custom',
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

    result = {}

    def save_profile():
        with app.app_context():
            result['value'] = profile_manager.upsert_profile(
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

    worker = threading.Thread(target=save_profile, daemon=True)
    worker.start()
    worker.join(timeout=2)

    assert worker.is_alive() is False
    assert result['value'][1] is None


@pytest.mark.parametrize('mode', ['command', 'command_set'])
def test_post_connect_resolution_completes_without_reentrant_store_lock(
    app, mode
):
    from app import command_manager, command_set_manager, post_connect_manager

    with app.app_context():
        user_id = _create_user(app, f'migration-resolve-lock-{mode}')
        if mode == 'command':
            reference = command_manager.add_user_command(
                user_id, 'Reference', 'true', '', 'Reference',
                ['all'], 'custom',
            )
            payload = {
                'startup_mode': 'command',
                'command_id': reference['id'],
            }
        else:
            reference, error = command_set_manager.upsert_command_set(
                user_id,
                {
                    'name': 'Reference',
                    'steps': [{'type': 'inline', 'command': 'true'}],
                },
            )
            assert error is None
            payload = {
                'startup_mode': 'command_set',
                'command_set_id': reference['id'],
            }

    result = {}

    def resolve():
        with app.app_context():
            result['value'] = post_connect_manager.resolve_configuration(
                user_id, payload
            )

    worker = threading.Thread(target=resolve, daemon=True)
    worker.start()
    worker.join(timeout=2)

    assert worker.is_alive() is False
    assert result['value'] == ('true', None)
