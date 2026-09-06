"""Corruption handling for per-user jump-host storage."""

from contextlib import contextmanager
import threading

import pytest

from app.storage_errors import StorageCorruptionError


def _create_user(app):
    from app.models import User, db

    with app.app_context():
        user = User(username='jump-store-user', password_hash='unused')
        db.session.add(user)
        db.session.commit()
        return user.id


def test_add_jump_host_preserves_corrupt_storage(app):
    from app import jump_host_manager

    user_id = _create_user(app)
    corrupt = b'{"jump_hosts": ['
    with app.app_context():
        path = jump_host_manager._get_file(user_id)
        path.write_bytes(corrupt)

        with pytest.raises(StorageCorruptionError) as exc_info:
            jump_host_manager.add_jump_host(
                user_id, 'Bastion', 'bastion.example', 22, 'deploy', 'password'
            )

        assert exc_info.value.path == path
        assert path.read_bytes() == corrupt


def test_missing_jump_host_store_keeps_empty_default(app):
    from app import jump_host_manager

    user_id = _create_user(app)
    with app.app_context():
        assert jump_host_manager.load_jump_hosts(user_id) == []


def test_referenced_jump_host_cannot_be_deleted_and_reports_safe_profile_names(
    app,
):
    from app import jump_host_manager, profile_manager

    user_id = _create_user(app)
    with app.app_context():
        jump_host, error = jump_host_manager.add_jump_host(
            user_id, 'Bastion', 'bastion.example', 22, 'deploy', 'password'
        )
        assert error is None
        assert profile_manager.save_profiles(user_id, [{
            'id': 'profile-1',
            'name': 'Production',
            'host': 'target.example',
            'port': 22,
            'username': 'deploy',
            'auth_type': 'password',
            'jump_host_id': jump_host['id'],
        }])

        result = jump_host_manager.delete_jump_host(
            user_id, jump_host['id']
        )

        assert result == (
            False,
            'Jump host is used by 1 profile',
            ['Production'],
        )
        assert jump_host_manager.load_jump_hosts(user_id) == [jump_host]


def test_missing_jump_host_delete_is_not_found(app):
    from app import jump_host_manager

    user_id = _create_user(app)
    with app.app_context():
        assert jump_host_manager.delete_jump_host(
            user_id, 'missing'
        ) == (False, 'Jump host not found', [])


def test_jump_host_delete_and_stale_profile_edit_are_serialized(app, monkeypatch):
    from app import jump_host_manager, profile_manager

    user_id = _create_user(app)
    with app.app_context():
        jump_host, error = jump_host_manager.add_jump_host(
            user_id, 'Bastion', 'bastion.example', 22, 'deploy', 'password'
        )
        assert error is None

    profiles_read = threading.Event()
    continue_delete = threading.Event()
    profile_done = threading.Event()
    delete_result = {}
    profile_result = {}
    real_load = jump_host_manager._load_profile_references

    def paused_load_profiles(value):
        result = real_load(value)
        profiles_read.set()
        assert continue_delete.wait(timeout=2)
        return result

    monkeypatch.setattr(
        jump_host_manager, '_load_profile_references', paused_load_profiles
    )

    def delete():
        with app.app_context():
            delete_result['value'] = jump_host_manager.delete_jump_host(
                user_id, jump_host['id']
            )

    def save_stale_profile():
        with app.app_context():
            profile_result['value'] = profile_manager.upsert_profile(user_id, {
                'name': 'Stale editor',
                'host': 'target.example',
                'port': 22,
                'username': 'deploy',
                'auth_type': 'password',
                'jump_host_id': jump_host['id'],
            })
        profile_done.set()

    deleter = threading.Thread(target=delete, daemon=True)
    writer = threading.Thread(target=save_stale_profile, daemon=True)
    try:
        deleter.start()
        assert profiles_read.wait(timeout=2)
        writer.start()
        assert profile_done.wait(timeout=0.2) is False
    finally:
        continue_delete.set()
        deleter.join(timeout=2)
        writer.join(timeout=2)

    assert deleter.is_alive() is False
    assert writer.is_alive() is False
    assert delete_result['value'] == (True, None, [])
    assert profile_result['value'] == (None, 'Jump host not found')


def test_jump_host_count_quota_is_atomic_and_delete_remains_available(
    app,
    monkeypatch,
):
    import config
    from app import jump_host_manager

    user_id = _create_user(app)
    monkeypatch.setattr(config, 'JUMP_HOST_MAX_RECORDS', 1)
    with app.app_context():
        first, error = jump_host_manager.add_jump_host(
            user_id, 'First', 'first.example', 22, 'deploy', 'password'
        )
        assert error is None

        second, error = jump_host_manager.add_jump_host(
            user_id, 'Second', 'second.example', 22, 'deploy', 'password'
        )

        assert second is None
        assert error.startswith('Connection storage quota exceeded:')
        assert jump_host_manager.load_jump_hosts(user_id) == [first]
        assert jump_host_manager.delete_jump_host(
            user_id, first['id']
        ) == (True, None, [])


def test_jump_host_cannot_reference_another_users_ssh_key(
    app,
    rsa_private_key_pem,
):
    from app import jump_host_manager, key_manager
    from app.models import User, db

    attacker_id = _create_user(app)
    with app.app_context():
        owner = User(username='jump-key-owner', password_hash='unused')
        db.session.add(owner)
        db.session.commit()
        key, error = key_manager.save_key(
            owner.id, 'Owner key', rsa_private_key_pem
        )
        assert error is None

        jump_host, error = jump_host_manager.add_jump_host(
            attacker_id,
            'Foreign key',
            'bastion.example',
            22,
            'deploy',
            'key',
            key['id'],
        )

    assert jump_host is None
    assert error == 'SSH key not found'


def test_jump_host_create_uses_cross_store_coordinator_before_store_lock(
    app,
    monkeypatch,
):
    from app import jump_host_manager
    from app.storage_utils import storage_lock as real_storage_lock

    user_id = _create_user(app)
    requested = []

    @contextmanager
    def instrumented_storage_lock(key):
        requested.append(key)
        with real_storage_lock(key):
            yield

    monkeypatch.setattr(
        jump_host_manager,
        'storage_lock',
        instrumented_storage_lock,
    )

    with app.app_context():
        jump_host, error = jump_host_manager.add_jump_host(
            user_id,
            'Bastion',
            'bastion.example',
            22,
            'deploy',
            'password',
        )

    assert error is None
    assert jump_host is not None
    assert requested == [
        f'command-config:{user_id}',
        f'jump_hosts:{user_id}',
    ]


def test_legacy_oversized_jump_host_store_is_not_listed_but_can_be_deleted(
    app,
    monkeypatch,
):
    import json
    import config
    from app import jump_host_manager
    from app.connection_storage_policy import ConnectionStorageLimitError
    from app.storage_migrations import CURRENT_STORAGE_VERSIONS

    user_id = _create_user(app)
    jump_host = {
        'id': 'legacy-large',
        'name': 'Legacy',
        'host': 'bastion.example',
        'port': 22,
        'username': 'deploy',
        'auth_type': 'password',
        'future': 'x' * 1024,
    }
    with app.app_context():
        path = jump_host_manager._get_file(user_id)
        path.write_text(json.dumps({
            'schema_version': CURRENT_STORAGE_VERSIONS['jump_hosts'],
            'jump_hosts': [jump_host],
        }), encoding='utf-8')
        monkeypatch.setattr(config, 'CONNECTION_STORE_MAX_BYTES', 256)

        with pytest.raises(ConnectionStorageLimitError):
            jump_host_manager.load_jump_hosts(user_id)
        with pytest.raises(ConnectionStorageLimitError):
            jump_host_manager.get_jump_host(user_id, jump_host['id'])
        added, error = jump_host_manager.add_jump_host(
            user_id, 'New', 'new.example', 22, 'deploy', 'password'
        )
        assert added is None
        assert error == (
            'Connection storage quota exceeded: stored data exceeds its byte limit'
        )
        assert jump_host_manager.delete_jump_host(
            user_id, jump_host['id']
        ) == (True, None, [])
        assert jump_host_manager.load_jump_hosts(user_id) == []
