"""Corruption handling for per-user jump-host storage."""

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
