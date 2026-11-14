"""SOCKS metadata, route ownership, and shared storage budgets."""

import json
import threading

import pytest

from app.storage_errors import StorageCorruptionError


def _create_user(app, name='socks-store-user'):
    from app.models import User, db

    with app.app_context():
        user = User(username=name, password_hash='unused')
        db.session.add(user)
        db.session.commit()
        return user.id


def _profile(**fields):
    return {'name': 'Target', 'host': 'target.example', 'port': 22,
            'username': 'deploy', 'auth_type': 'password', **fields}


def test_socks_proxy_crud_is_owned_and_preserves_identity_on_update(app):
    from app import socks_proxy_manager as manager

    user_id = _create_user(app)
    other_id = _create_user(app, 'other-socks-user')
    with app.app_context():
        assert manager.load_socks_proxies(user_id) == []
        proxy, error = manager.add_socks_proxy(user_id, ' Proxy ', 'proxy.example', 1080)
        assert error is None
        assert proxy['username'] == ''
        assert proxy['remote_dns'] is True
        assert manager.get_socks_proxy(other_id, proxy['id']) is None
        missing, error = manager.add_socks_proxy(other_id, 'Foreign', 'other.example', 1080,
                                                 socks_proxy_id=proxy['id'])
        assert missing is None and 'not found' in error
        updated, error = manager.add_socks_proxy(user_id, 'Edited', 'next.example', 1081,
            'password', 'proxy-user', False, socks_proxy_id=proxy['id'])
        assert error is None
        assert updated['id'] == proxy['id']
        assert updated['created_at'] == proxy['created_at']
        assert manager.get_socks_proxy(user_id, proxy['id']) == updated
        assert manager.delete_socks_proxy(other_id, proxy['id'])[0] is False
        assert manager.delete_socks_proxy(user_id, proxy['id']) == (True, None, [])
        assert manager.load_socks_proxies(user_id) == []


@pytest.mark.parametrize('changes', [
    {'name': ''}, {'name': 17}, {'name': 'x' * 513}, {'host': []},
    {'host': 'https://proxy.example'}, {'port': True}, {'port': '1080'},
    {'port': 1080.0}, {'port': 0}, {'port': 65536}, {'auth_type': 'key'},
    {'auth_type': 'PASSWORD'}, {'username': None}, {'username': 'ignored'},
    {'auth_type': 'password', 'username': ''},
    {'auth_type': 'password', 'username': 'é' * 128},
    {'auth_type': 'password', 'username': '\ud800'},
    {'remote_dns': 'false'}, {'remote_dns': 1}, {'remote_dns': None},
    {'socks_proxy_id': 7}, {'socks_proxy_id': 'a' * 65},
])
def test_invalid_proxy_metadata_never_creates_a_store(app, changes):
    from app import socks_proxy_manager as manager

    user_id = _create_user(app)
    fields = {'name': 'Proxy', 'host': 'proxy.example', 'port': 1080,
              'auth_type': 'none', 'username': '', 'remote_dns': True, **changes}
    with app.app_context():
        proxy, error = manager.add_socks_proxy(user_id, **fields)
        assert proxy is None and error
        assert not manager._get_file(user_id).exists()


def test_proxy_username_accepts_full_rfc1929_utf8_budget(app):
    from app import socks_proxy_manager as manager

    user_id = _create_user(app)
    with app.app_context():
        proxy, error = manager.add_socks_proxy(user_id, 'Proxy', '::1', 1080,
            'password', 'é' * 127 + 'x')
        assert error is None
        assert proxy['username'] == 'é' * 127 + 'x'


@pytest.mark.parametrize('changes', [
    {'password': 'never-persist'}, {'credential_id': 'secret-reference'},
    {'unknown': True}, {'auth_type': 'key'}, {'remote_dns': 1}, {'port': 0},
    {'port': True}, {'username': None}, {'host': 'bad/host'},
])
def test_socks_schema_rejects_invalid_records_without_overwrite(app, changes):
    from app import socks_proxy_manager as manager

    user_id = _create_user(app)
    with app.app_context():
        record = {'id': 'proxy-1', 'name': 'Proxy', 'host': 'proxy.example',
                  'port': 1080, 'auth_type': 'none', 'username': '',
                  'remote_dns': True, 'created_at': '2026-01-01', **changes}
        path = manager._get_file(user_id)
        raw = json.dumps({'socks_proxies': [record]}).encode()
        path.write_bytes(raw)
        with pytest.raises(StorageCorruptionError):
            manager.add_socks_proxy(user_id, 'Another', 'next.example', 1080)
        assert path.read_bytes() == raw


def test_corrupt_socks_json_is_preserved(app):
    from app import socks_proxy_manager as manager

    user_id = _create_user(app)
    with app.app_context():
        path = manager._get_file(user_id)
        path.write_bytes(b'{"socks_proxies": [')
        with pytest.raises(StorageCorruptionError):
            manager.delete_socks_proxy(user_id, 'any')
        assert path.read_bytes() == b'{"socks_proxies": ['


def _write_duplicate_proxy_ids(manager, user_id):
    record = {
        'id': 'duplicate-proxy', 'name': 'Proxy', 'host': 'proxy.example',
        'port': 1080, 'auth_type': 'none', 'username': '',
        'remote_dns': True, 'created_at': '2026-01-01',
    }
    raw = json.dumps({'socks_proxies': [
        record, {**record, 'host': 'other.example'},
    ]}).encode('utf-8')
    path = manager._get_file(user_id)
    path.write_bytes(raw)
    return path, raw


def test_duplicate_proxy_ids_reject_mutation_without_overwrite(app):
    from app import socks_proxy_manager as manager

    user_id = _create_user(app)
    with app.app_context():
        path, original = _write_duplicate_proxy_ids(manager, user_id)
        with pytest.raises(StorageCorruptionError):
            manager.add_socks_proxy(user_id, 'Edited', 'edited.example', 1080,
                                    socks_proxy_id='duplicate-proxy')
        assert path.read_bytes() == original
        assert list(path.parent.glob('socks_proxies.json.*.bak')) == []


def test_live_proxy_lookup_rejects_duplicate_ids(app):
    from app import socks_proxy_manager as manager

    user_id = _create_user(app)
    with app.app_context():
        path, original = _write_duplicate_proxy_ids(manager, user_id)
        with pytest.raises(StorageCorruptionError):
            manager.get_socks_proxy(user_id, 'duplicate-proxy')
        assert path.read_bytes() == original


def test_proxy_callback_failure_rolls_back_storage(app):
    from app import socks_proxy_manager as manager

    user_id = _create_user(app)
    with app.app_context():
        original, error = manager.add_socks_proxy(user_id, 'Original', 'proxy.example', 1080)
        assert error is None
        path = manager._get_file(user_id)
        before = path.read_bytes()

        def fail(_record):
            raise ValueError('Credential transaction failed')

        result, error = manager.add_socks_proxy(user_id, 'Edited', 'next.example', 1080,
            socks_proxy_id=original['id'], on_created=fail)
        assert result is None and error
        assert path.read_bytes() == before


def test_socks_count_limit_and_reference_protection(app, monkeypatch):
    import config
    from app import profile_manager, socks_proxy_manager as manager

    user_id = _create_user(app)
    with app.app_context():
        monkeypatch.setattr(config, 'SOCKS_PROXY_MAX_RECORDS', 1)
        proxy, error = manager.add_socks_proxy(user_id, 'Proxy', 'proxy.example', 1080)
        assert error is None
        assert manager.add_socks_proxy(user_id, 'Second', 'next.example', 1080)[0] is None
        for index in range(23):
            profile, error = profile_manager.upsert_profile(user_id,
                _profile(name=f'Host {index}', socks_proxy_id=proxy['id']))
            assert error is None
        deleted, error, usages = manager.delete_socks_proxy(user_id, proxy['id'])
        assert deleted is False
        assert '23 profiles' in error and 'first 20' in error
        assert usages == [f'Host {index}' for index in range(20)]
        assert manager.get_socks_proxy(user_id, proxy['id']) is not None


@pytest.mark.parametrize('route', [
    {'socks_proxy_id': 'missing'}, {'socks_proxy_id': 123},
    {'socks_proxy_id': []}, {'socks_proxy_id': 'a' * 65},
    {'socks_proxy_id': 'proxy', 'jump_host_id': 'jump'},
    {'socks_proxy_id': 'proxy', 'auth_type': 'tailscale'},
])
def test_profile_rejects_invalid_or_conflicting_socks_routes(app, route):
    from app import profile_manager

    user_id = _create_user(app)
    with app.app_context():
        for skip_duplicate in (False, True):
            result, error = profile_manager.upsert_profile(user_id, _profile(**route),
                skip_duplicate=skip_duplicate)
            assert result is None and error
        assert profile_manager.load_profiles(user_id) == []


def test_profile_socks_route_roundtrip_live_ownership_and_duplicate_check(app):
    from app import profile_manager, socks_proxy_manager as manager

    user_id = _create_user(app)
    other_id = _create_user(app, 'other-profile-owner')
    with app.app_context():
        proxy, error = manager.add_socks_proxy(user_id, 'Proxy', 'proxy.example', 1080)
        assert error is None
        assert profile_manager.upsert_profile(other_id,
            _profile(socks_proxy_id=proxy['id'])) == (None, 'SOCKS proxy not found')
        direct, error = profile_manager.upsert_profile(user_id, _profile())
        assert error is None
        routed, error = profile_manager.upsert_profile(user_id,
            _profile(name='Routed', socks_proxy_id=proxy['id']), skip_duplicate=True)
        assert error is None
        assert profile_manager.get_profile(user_id, routed['id'])['socks_proxy_id'] == proxy['id']
        assert profile_manager.upsert_profile(user_id,
            _profile(name='Duplicate', socks_proxy_id=proxy['id']), skip_duplicate=True)[0] is None
        assert profile_manager.cache_greeting_platforms(user_id,
            {routed['id']: (('target.example', 22), 'linux')}) == 0
        cleared, error = profile_manager.upsert_profile(user_id,
            _profile(id=routed['id'], name='Cleared', socks_proxy_id=None))
        assert error is None and not cleared.get('socks_proxy_id')
        assert direct['id'] != routed['id']


def test_all_stores_include_both_siblings_in_combined_byte_budget(app, monkeypatch):
    import config
    from app import profile_manager, jump_host_manager, socks_proxy_manager as manager

    user_id = _create_user(app)
    with app.app_context():
        assert profile_manager.upsert_profile(user_id, _profile())[1] is None
        assert jump_host_manager.add_jump_host(user_id, 'Jump', 'jump.example', 22,
                                                'deploy', 'password')[1] is None
        assert manager.add_socks_proxy(user_id, 'Proxy', 'proxy.example', 1080)[1] is None
        paths = [profile_manager.get_user_profiles_file(user_id),
                 jump_host_manager._get_file(user_id), manager._get_file(user_id)]
        before = [path.read_bytes() for path in paths]
        monkeypatch.setattr(config, 'CONNECTION_CONFIG_MAX_BYTES', sum(map(len, before)))
        assert profile_manager.upsert_profile(user_id, _profile(name='Big' * 40,
            host='next.example', startup_commands='x' * 1000))[0] is None
        assert jump_host_manager.add_jump_host(user_id, 'Big' * 40, 'next.example', 22,
                                               'deploy', 'password')[0] is None
        assert manager.add_socks_proxy(user_id, 'Big' * 40, 'next.example', 1080)[0] is None
        assert [path.read_bytes() for path in paths] == before


def test_shared_budget_deduplicates_siblings_and_own_path(tmp_path, monkeypatch):
    import config
    from app.connection_storage_policy import enforce_store_transition

    path = tmp_path / 'own.json'
    path.write_bytes(b'0' * 500)
    sibling = tmp_path / 'sibling.json'
    sibling.write_bytes(b'0' * 100)
    monkeypatch.setattr(config, 'CONNECTION_CONFIG_MAX_BYTES', 610)
    payload = enforce_store_transition(path=path, other_path=sibling,
        other_paths=[sibling, tmp_path / '.' / 'sibling.json', path],
        prospective_document={'data': 'x' * 490}, prospective_count=1,
        previous_count=1, maximum_count=100)
    assert 500 < len(payload) <= 510


def test_socks_recovery_cli_bounds_output_and_deletes_oversized_store(app, monkeypatch):
    import config
    from app import socks_proxy_manager as manager
    from app.connection_storage_policy import ConnectionStorageLimitError

    user_id = _create_user(app)
    with app.app_context():
        proxy, error = manager.add_socks_proxy(user_id, 'Proxy', 'proxy.example', 1080,
            'password', 'private-username')
        assert error is None
        monkeypatch.setattr(config, 'CONNECTION_STORE_MAX_BYTES', 100)
        with pytest.raises(ConnectionStorageLimitError):
            manager.load_socks_proxies(user_id)
    runner = app.test_cli_runner()
    base = ['--username', 'socks-store-user', '--kind', 'socks-proxies']
    assert runner.invoke(args=['connection-store', 'list', *base]).exit_code != 0
    result = runner.invoke(args=['connection-store', 'list', *base, '--confirm-offline'])
    assert result.exit_code == 0, result.output
    assert 'private-username' not in result.output
    summary = json.loads(result.output)
    assert summary['count'] == 1
    selector = summary['records'][0]['selector']
    result = runner.invoke(args=['connection-store', 'delete', *base,
                                '--selector', selector, '--confirm-offline'])
    assert result.exit_code == 0, result.output
    with app.app_context():
        assert manager.load_socks_proxies(user_id) == []


def test_session_schema_additively_preserves_legacy_rows(app):
    from sqlalchemy import text
    from app.models import db, ensure_ssh_session_columns

    with app.app_context():
        db.session.execute(text('DROP TABLE ssh_sessions'))
        db.session.execute(text('CREATE TABLE ssh_sessions (id INTEGER PRIMARY KEY, session_id VARCHAR(36))'))
        db.session.execute(text("INSERT INTO ssh_sessions (id, session_id) VALUES (1, 'legacy')"))
        db.session.commit()
        ensure_ssh_session_columns()
        ensure_ssh_session_columns()
        row = db.session.execute(text('SELECT session_id, socks_proxy_id, via_socks FROM ssh_sessions')).one()
        assert tuple(row) == ('legacy', None, 0)


@pytest.mark.parametrize('fields', [
    {'socks_proxy_id': 'x' * 65},
    {'socks_proxy_id': 'proxy', 'jump_host_id': 'jump'},
    {'socks_proxy_id': 'proxy', 'auth_type': 'tailscale'},
])
def test_profile_store_rejects_malformed_socks_routes(app, fields):
    from app import profile_manager

    user_id = _create_user(app)
    with app.app_context():
        assert profile_manager.save_profiles(user_id, [
            _profile(id='profile', **fields)
        ]) is False
        assert not profile_manager.get_user_profiles_file(user_id).exists()


def test_socks_store_migration_rejects_unknown_document_fields(app):
    from app import socks_proxy_manager as manager

    user_id = _create_user(app)
    with app.app_context():
        path = manager._get_file(user_id)
        original = b'{"socks_proxies": [], "password": "never-write-this"}'
        path.write_bytes(original)
        with pytest.raises(StorageCorruptionError):
            manager.load_socks_proxies(user_id)
        assert path.read_bytes() == original


def test_socks_recovery_reference_guard_and_stale_selector(app, monkeypatch):
    import config
    from app import profile_manager, socks_proxy_manager as manager

    user_id = _create_user(app)
    other_id = _create_user(app, 'other-recovery-user')
    with app.app_context():
        proxy, error = manager.add_socks_proxy(user_id, 'Proxy', 'proxy.example', 1080)
        assert error is None
        selector = manager.load_socks_proxy_recovery_summaries(user_id)[0]['selector']
        assert manager.delete_socks_proxy_recovery_record(other_id, selector)[0] is False
        manager.add_socks_proxy(user_id, 'Updated', 'proxy.example', 1080,
                                socks_proxy_id=proxy['id'])
        assert manager.delete_socks_proxy_recovery_record(user_id, selector)[0] is False
        profile, error = profile_manager.add_profile(user_id, 'Target', 'target.example',
            22, 'deploy', 'password', socks_proxy_id=proxy['id'])
        assert error is None and profile['socks_proxy_id'] == proxy['id']
        selector = manager.load_socks_proxy_recovery_summaries(user_id)[0]['selector']
        monkeypatch.setattr(config, 'CONNECTION_STORE_MAX_BYTES', 100)
        deleted, error, usages = manager.delete_socks_proxy_recovery_record(user_id, selector)
        assert deleted is False and '1 profile' in error
        assert usages == ['Target']


def test_socks_recovery_enforces_hard_byte_and_record_ceilings(app, monkeypatch):
    import config
    from app import socks_proxy_manager as manager
    from app.connection_storage_policy import ConnectionStorageLimitError

    user_id = _create_user(app)
    with app.app_context():
        assert manager.add_socks_proxy(user_id, 'Proxy', 'proxy.example', 1080)[1] is None
        original = manager._get_file(user_id).read_bytes()
        monkeypatch.setattr(config, 'CONNECTION_STORE_RECOVERY_MAX_RECORDS', 0)
        with pytest.raises(ConnectionStorageLimitError):
            manager.load_socks_proxy_recovery_summaries(user_id)
        monkeypatch.setattr(config, 'CONNECTION_STORE_RECOVERY_MAX_RECORDS', 100)
        monkeypatch.setattr(config, 'CONNECTION_STORE_RECOVERY_MAX_BYTES', len(original) - 1)
        with pytest.raises(ConnectionStorageLimitError):
            manager.load_socks_proxy_recovery_summaries(user_id)
        assert manager._get_file(user_id).read_bytes() == original


def test_oversized_socks_store_cannot_grow_and_recovery_shrinks_it(app, monkeypatch):
    import config
    from app import socks_proxy_manager as manager

    user_id = _create_user(app)
    with app.app_context():
        proxy, error = manager.add_socks_proxy(user_id, 'Proxy', 'proxy.example', 1080)
        assert error is None
        path = manager._get_file(user_id)
        original = path.read_bytes()
        monkeypatch.setattr(config, 'CONNECTION_STORE_MAX_BYTES', len(original) - 1)
        result, error = manager.add_socks_proxy(user_id, 'Second', 'other.example', 1080)
        assert result is None and 'quota exceeded' in error
        assert path.read_bytes() == original
        selector = manager.load_socks_proxy_recovery_summaries(user_id)[0]['selector']
        assert manager.delete_socks_proxy_recovery_record(user_id, selector) == (True, None, [])
        assert path.stat().st_size < len(original)
        assert manager.load_socks_proxies(user_id) == []


def test_socks_delete_and_stale_profile_edit_are_serialized(app, monkeypatch):
    from app import socks_proxy_manager as manager, profile_manager

    user_id = _create_user(app)
    with app.app_context():
        proxy, error = manager.add_socks_proxy(user_id, 'Proxy', 'proxy.example', 1080)
        assert error is None
    references_read = threading.Event()
    continue_delete = threading.Event()
    profile_done = threading.Event()
    results = {}
    real_load = manager._load_profile_references

    def pause_after_read(value):
        profiles = real_load(value)
        references_read.set()
        assert continue_delete.wait(timeout=3)
        return profiles

    monkeypatch.setattr(manager, '_load_profile_references', pause_after_read)

    def delete():
        with app.app_context():
            results['delete'] = manager.delete_socks_proxy(user_id, proxy['id'])

    def write_profile():
        with app.app_context():
            results['profile'] = profile_manager.upsert_profile(user_id,
                _profile(socks_proxy_id=proxy['id']))
        profile_done.set()

    deleter = threading.Thread(target=delete, daemon=True)
    writer = threading.Thread(target=write_profile, daemon=True)
    try:
        deleter.start()
        assert references_read.wait(timeout=3)
        writer.start()
        assert not profile_done.wait(timeout=0.2)
    finally:
        continue_delete.set()
        deleter.join(timeout=3)
        if writer.ident is not None:
            writer.join(timeout=3)
    assert not deleter.is_alive() and not writer.is_alive()
    assert results['delete'] == (True, None, [])
    assert results['profile'] == (None, 'SOCKS proxy not found')
