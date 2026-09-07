"""Offline recovery CLI contracts for quarantined legacy connection stores."""

import json
import re

import pytest


def _run_cli_child(
    flask_app,
    arguments,
    results,
    *,
    start=None,
    ready=None,
    initialization_started=None,
):
    try:
        if initialization_started is not None:
            import app as app_package

            original_initialize = app_package._initialize_persistent_storage

            def observe_initialize(application):
                initialization_started.set()
                return original_initialize(application)

            app_package._initialize_persistent_storage = observe_initialize
        if ready is not None:
            ready.set()
        if start is not None and not start.wait(timeout=5):
            raise RuntimeError('child CLI start was not released')
        result = flask_app.test_cli_runner().invoke(args=arguments)
        results.put(('result', result.exit_code, result.output))
    except BaseException as exc:
        results.put(('exception', 1, repr(exc)))


def _run_paused_profile_delete_child(
    flask_app,
    arguments,
    loaded,
    release,
    results,
):
    from app import profile_manager

    original_load = profile_manager._load_profiles_for_recovery_delete

    def load_then_pause(*args, **kwargs):
        value = original_load(*args, **kwargs)
        loaded.set()
        if not release.wait(timeout=5):
            raise RuntimeError('paused recovery delete was not released')
        return value

    profile_manager._load_profiles_for_recovery_delete = load_then_pause
    _run_cli_child(flask_app, arguments, results)


def _run_contended_profile_delete_child(
    flask_app,
    arguments,
    blocked,
    results,
):
    from app import backup_coordination

    original_try_lock = backup_coordination._try_lock

    def observe_try_lock(descriptor):
        acquired = original_try_lock(descriptor)
        if not acquired:
            blocked.set()
        return acquired

    backup_coordination._try_lock = observe_try_lock
    _run_cli_child(flask_app, arguments, results)


def _create_user(app, username):
    from app.models import User, db

    with app.app_context():
        user = User(username=username, password_hash='not-used')
        db.session.add(user)
        db.session.commit()
        return user.id


def test_profile_recovery_cli_lists_no_secrets_and_deletes_exact_record(
    app,
    monkeypatch,
):
    import config
    from app import profile_manager
    from app.connection_storage_policy import ConnectionStorageLimitError
    from app.storage_migrations import CURRENT_STORAGE_VERSIONS

    username = 'profile-recovery-cli'
    user_id = _create_user(app, username)
    secret = 'never-print-this-startup-command'
    with app.app_context():
        path = profile_manager.get_user_profiles_file(user_id)
        path.write_text(json.dumps({
            'schema_version': CURRENT_STORAGE_VERSIONS['profiles'],
            'profiles': [{
                'id': 'legacy-profile-id',
                'name': 'Legacy profile',
                'host': 'legacy.example',
                'startup_commands': secret,
                'future': 'x' * 2048,
            }],
        }), encoding='utf-8')
        monkeypatch.setattr(config, 'CONNECTION_STORE_MAX_BYTES', 256)
        with pytest.raises(ConnectionStorageLimitError):
            profile_manager.load_profiles(user_id)

    runner = app.test_cli_runner()
    refused = runner.invoke(args=[
        'connection-store', 'list', '--username', username,
        '--kind', 'profiles',
    ])
    assert refused.exit_code != 0
    assert '--confirm-offline' in refused.output

    listed = runner.invoke(args=[
        'connection-store', 'list', '--username', username,
        '--kind', 'profiles', '--confirm-offline',
    ])
    assert listed.exit_code == 0, listed.output
    assert secret not in listed.output
    listing = json.loads(listed.output)
    assert listing == {
        'count': 1,
        'kind': 'profiles',
        'records': [{
            'host': 'legacy.example',
            'id': 'legacy-profile-id',
            'name': 'Legacy profile',
            'selector': listing['records'][0]['selector'],
        }],
    }
    selector = listing['records'][0]['selector']
    assert re.fullmatch(r'r1:0:[0-9a-f]{64}', selector)

    deleted = runner.invoke(args=[
        'connection-store', 'delete', '--username', username,
        '--kind', 'profiles', '--selector', selector,
        '--confirm-offline',
    ])
    assert deleted.exit_code == 0, deleted.output
    with app.app_context():
        assert profile_manager.load_profiles(user_id) == []


def test_jump_host_recovery_cli_preserves_reference_protection(
    app,
    monkeypatch,
):
    import config
    from app import jump_host_manager, profile_manager
    from app.storage_migrations import CURRENT_STORAGE_VERSIONS

    username = 'jump-recovery-cli'
    user_id = _create_user(app, username)
    with app.app_context():
        jump_path = jump_host_manager._get_file(user_id)
        jump_path.write_text(json.dumps({
            'schema_version': CURRENT_STORAGE_VERSIONS['jump_hosts'],
            'jump_hosts': [{
                'id': 'legacy-jump-id',
                'name': 'Legacy jump',
                'host': 'jump.example',
                'port': 22,
                'username': 'deploy',
                'auth_type': 'password',
                'future': 'x' * 2048,
            }],
        }), encoding='utf-8')
        assert profile_manager.save_profiles(user_id, [{
            'id': 'profile-id',
            'name': 'Production',
            'host': 'target.example',
            'port': 22,
            'username': 'deploy',
            'auth_type': 'password',
            'jump_host_id': 'legacy-jump-id',
        }])
        monkeypatch.setattr(config, 'CONNECTION_STORE_MAX_BYTES', 256)

    runner = app.test_cli_runner()
    listed = runner.invoke(args=[
        'connection-store', 'list', '--username', username,
        '--kind', 'jump-hosts', '--confirm-offline',
    ])
    assert listed.exit_code == 0, listed.output
    records = json.loads(listed.output)['records']
    assert records == [{
        'host': 'jump.example',
        'id': 'legacy-jump-id',
        'name': 'Legacy jump',
        'selector': records[0]['selector'],
    }]

    refused = runner.invoke(args=[
        'connection-store', 'delete', '--username', username,
        '--kind', 'jump-hosts', '--selector', records[0]['selector'],
        '--confirm-offline',
    ])
    assert refused.exit_code != 0
    assert 'used by 1 profile' in refused.output


def test_profile_recovery_cli_selectors_are_unique_and_delete_one_record(
    app,
    monkeypatch,
):
    import config
    from app import profile_manager
    from app.storage_migrations import CURRENT_STORAGE_VERSIONS

    username = 'profile-recovery-selector-cli'
    user_id = _create_user(app, username)
    shared_prefix = 'x' * 128
    profiles = [
        {
            'id': f'{shared_prefix}-first',
            'name': 'First collision',
        },
        {
            'id': f'{shared_prefix}-second',
            'name': 'Second collision',
        },
        {
            'id': 'duplicate-id',
            'name': 'First duplicate',
        },
        {
            'id': 'duplicate-id',
            'name': 'Second duplicate',
        },
    ]
    with app.app_context():
        path = profile_manager.get_user_profiles_file(user_id)
        path.write_text(json.dumps({
            'schema_version': CURRENT_STORAGE_VERSIONS['profiles'],
            'profiles': profiles,
        }), encoding='utf-8')
        monkeypatch.setattr(config, 'CONNECTION_STORE_MAX_BYTES', 128)

    runner = app.test_cli_runner()
    listed = runner.invoke(args=[
        'connection-store', 'list', '--username', username,
        '--kind', 'profiles', '--confirm-offline',
    ])
    assert listed.exit_code == 0, listed.output
    records = json.loads(listed.output)['records']
    selectors = [record['selector'] for record in records]
    assert len(set(selectors)) == len(profiles)
    assert records[0]['id'] == records[1]['id'] == shared_prefix
    assert records[2]['id'] == records[3]['id'] == 'duplicate-id'

    profiles[0]['name'] = 'Changed collision'
    with app.app_context():
        path.write_text(json.dumps({
            'schema_version': CURRENT_STORAGE_VERSIONS['profiles'],
            'profiles': profiles,
        }), encoding='utf-8')
    changed = runner.invoke(args=[
        'connection-store', 'delete', '--username', username,
        '--kind', 'profiles', '--selector', records[0]['selector'],
        '--confirm-offline',
    ])
    assert changed.exit_code != 0
    assert 'list the store again' in changed.output

    deleted = runner.invoke(args=[
        'connection-store', 'delete', '--username', username,
        '--kind', 'profiles', '--selector', records[3]['selector'],
        '--confirm-offline',
    ])
    assert deleted.exit_code == 0, deleted.output
    with app.app_context():
        persisted = json.loads(path.read_text(encoding='utf-8'))['profiles']
    assert [profile['name'] for profile in persisted] == [
        'Changed collision',
        'Second collision',
        'First duplicate',
    ]

    stale = runner.invoke(args=[
        'connection-store', 'delete', '--username', username,
        '--kind', 'profiles', '--selector', records[3]['selector'],
        '--confirm-offline',
    ])
    assert stale.exit_code != 0
    assert 'list the store again' in stale.output
    with app.app_context():
        persisted = json.loads(path.read_text(encoding='utf-8'))['profiles']
    assert [profile['name'] for profile in persisted] == [
        'Changed collision',
        'Second collision',
        'First duplicate',
    ]


def test_parallel_recovery_deletes_are_cross_process_serialized(
    app,
    monkeypatch,
    tmp_path,
):
    import multiprocessing
    import config
    from app import profile_manager
    from app.models import db

    try:
        process_context = multiprocessing.get_context('fork')
    except ValueError:
        pytest.skip('requires multiprocessing fork support')

    username = 'profile-recovery-cross-process'
    user_id = _create_user(app, username)
    profiles = [
        {'id': 'first', 'name': 'First'},
        {'id': 'second', 'name': 'Second'},
    ]
    with app.app_context():
        assert profile_manager.save_profiles(user_id, profiles) is True
        summaries, error = profile_manager.load_profile_recovery_summaries(
            user_id
        )
        assert error is None
        path = profile_manager.get_user_profiles_file(user_id)
        db.session.remove()
        db.engine.dispose()

    monkeypatch.setattr(config, 'BACKUP_TEMP_DIR', tmp_path / 'operations')
    monkeypatch.setattr(config, 'BACKUP_OPERATION_TIMEOUT', 2)
    common = [
        'connection-store', 'delete', '--username', username,
        '--kind', 'profiles', '--confirm-offline', '--selector',
    ]
    # The first process removes ordinal 1. Once serialized, ordinal 0 retains
    # its selector and can be removed by the contender without a lost update.
    first_arguments = [*common, summaries[1]['selector']]
    second_arguments = [*common, summaries[0]['selector']]
    first_loaded = process_context.Event()
    release_first = process_context.Event()
    contender_blocked = process_context.Event()
    results = process_context.Queue()
    first = process_context.Process(
        target=_run_paused_profile_delete_child,
        args=(
            app,
            first_arguments,
            first_loaded,
            release_first,
            results,
        ),
    )
    second = process_context.Process(
        target=_run_contended_profile_delete_child,
        args=(app, second_arguments, contender_blocked, results),
    )
    try:
        first.start()
        assert first_loaded.wait(timeout=3)
        second.start()
        assert contender_blocked.wait(timeout=3)
        release_first.set()
        outcomes = [results.get(timeout=5), results.get(timeout=5)]
    finally:
        release_first.set()
        for process in (first, second):
            process.join(timeout=5)
            if process.is_alive():
                process.terminate()
                process.join(timeout=2)

    assert first.exitcode == 0
    assert second.exitcode == 0
    assert sorted(outcome[1] for outcome in outcomes) == [0, 0]
    assert all(
        'Deleted one profile recovery record.' in outcome[2]
        for outcome in outcomes
    )
    persisted = json.loads(path.read_text(encoding='utf-8'))
    assert persisted['profiles'] == []


@pytest.mark.parametrize('subcommand', ('list', 'delete'))
def test_connection_store_cli_reports_cross_process_operation_busy(
    app,
    monkeypatch,
    tmp_path,
    subcommand,
):
    import multiprocessing
    import config
    from app import profile_manager
    from app.backup_coordination import operation_lock
    from app.models import db

    try:
        process_context = multiprocessing.get_context('fork')
    except ValueError:
        pytest.skip('requires multiprocessing fork support')

    username = f'profile-recovery-busy-{subcommand}'
    user_id = _create_user(app, username)
    with app.app_context():
        assert profile_manager.save_profiles(user_id, [
            {'id': 'keep', 'name': 'Keep'},
        ]) is True
        summaries, error = profile_manager.load_profile_recovery_summaries(
            user_id
        )
        assert error is None
        path = profile_manager.get_user_profiles_file(user_id)
        original = path.read_bytes()
        db.session.remove()
        db.engine.dispose()

    monkeypatch.setattr(config, 'BACKUP_TEMP_DIR', tmp_path / 'operations')
    monkeypatch.setattr(config, 'BACKUP_OPERATION_TIMEOUT', 0.1)
    arguments = [
        'connection-store', subcommand, '--username', username,
        '--kind', 'profiles', '--confirm-offline',
    ]
    if subcommand == 'delete':
        arguments.extend(('--selector', summaries[0]['selector']))

    start = process_context.Event()
    ready = process_context.Event()
    initialization_started = process_context.Event()
    results = process_context.Queue()
    process = process_context.Process(
        target=_run_cli_child,
        args=(app, arguments, results),
        kwargs={
            'start': start,
            'ready': ready,
            'initialization_started': initialization_started,
        },
    )
    process.start()
    try:
        assert ready.wait(timeout=3)
        with operation_lock():
            start.set()
            outcome = results.get(timeout=5)
    finally:
        start.set()
        process.join(timeout=5)
        if process.is_alive():
            process.terminate()
            process.join(timeout=2)

    assert process.exitcode == 0
    assert outcome[0] == 'result'
    assert outcome[1] != 0
    assert 'another backup or restore operation is active' in outcome[2]
    assert initialization_started.is_set() is False
    assert path.read_bytes() == original
