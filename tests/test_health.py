from types import SimpleNamespace


def test_health_reports_process_liveness(client):
    response = client.get('/health')

    assert response.status_code == 200
    assert response.get_json() == {'status': 'ok'}


def test_ready_reports_success_when_dependencies_are_available(client):
    response = client.get('/ready')

    assert response.status_code == 200
    assert response.get_json() == {'status': 'ready'}


def test_ready_reports_runtime_shutdown(app, client, monkeypatch):
    lifecycle = app.extensions['runtime_lifecycle']
    monkeypatch.setattr(lifecycle, 'accepting_work', lambda: False)

    response = client.get('/ready')

    assert response.status_code == 503
    assert response.get_json() == {
        'status': 'not_ready',
        'failed': ['runtime'],
    }
    assert client.get('/health').get_json() == {'status': 'ok'}


def test_ready_reports_only_database_category_when_database_probe_fails(
    client,
    monkeypatch,
):
    from app.models import db

    def fail_database_probe(_statement):
        raise RuntimeError('database credentials leaked')

    monkeypatch.setattr(db.session, 'execute', fail_database_probe)

    response = client.get('/ready')

    assert response.status_code == 503
    assert response.get_json() == {
        'status': 'not_ready',
        'failed': ['database'],
    }
    assert b'database credentials leaked' not in response.data
    assert client.get('/health').get_json() == {'status': 'ok'}


def test_ready_reports_only_data_directory_category_when_write_probe_fails(
    client,
    monkeypatch,
):
    from app import health

    def fail_data_directory_probe():
        raise OSError('private filesystem path leaked')

    monkeypatch.setattr(
        health,
        '_probe_data_directory',
        fail_data_directory_probe,
    )

    response = client.get('/ready')

    assert response.status_code == 503
    assert response.get_json() == {
        'status': 'not_ready',
        'failed': ['data_directory'],
    }
    assert b'private filesystem path leaked' not in response.data
    assert client.get('/health').get_json() == {'status': 'ok'}


def test_database_readiness_recovers_after_a_failed_session_is_rolled_back(
    client,
    monkeypatch,
):
    from app.models import db

    original_execute = db.session.execute
    state = {'first_call': True, 'needs_rollback': False}

    def execute_with_failed_transaction(statement):
        if state['first_call']:
            state['first_call'] = False
            state['needs_rollback'] = True
            raise RuntimeError('transient database failure')
        if state['needs_rollback']:
            raise RuntimeError('database session still needs rollback')
        return original_execute(statement)

    def rollback_failed_transaction():
        state['needs_rollback'] = False

    monkeypatch.setattr(
        db.session,
        'execute',
        execute_with_failed_transaction,
    )
    monkeypatch.setattr(
        db.session,
        'rollback',
        rollback_failed_transaction,
    )

    assert client.get('/ready').status_code == 503

    recovered = client.get('/ready')
    assert recovered.status_code == 200
    assert recovered.get_json() == {'status': 'ready'}


def test_ready_reuses_a_recent_successful_write_probe(client, monkeypatch):
    from app import health

    probes = []
    real_probe = health._probe_data_directory
    monkeypatch.setattr(
        health, '_probe_data_directory',
        lambda: probes.append(1) or real_probe(),
    )
    now = [1000.0]
    monkeypatch.setattr(health, 'time', SimpleNamespace(monotonic=lambda: now[0]))

    for _ in range(5):
        response = client.get('/ready')
        assert response.status_code == 200
        assert response.get_json() == {'status': 'ready'}
    assert probes == [1]

    now[0] += health._DATA_DIRECTORY_PROBE_TTL
    assert client.get('/ready').status_code == 200
    assert probes == [1, 1]


def test_ready_never_reuses_a_failed_write_probe(client, monkeypatch):
    from app import health

    outcomes = [OSError('disk full'), None, None]
    probes = []

    def probe():
        probes.append(1)
        outcome = outcomes.pop(0)
        if outcome is not None:
            raise outcome

    monkeypatch.setattr(health, '_probe_data_directory', probe)
    monkeypatch.setattr(health, 'time', SimpleNamespace(monotonic=lambda: 1000.0))

    failed = client.get('/ready')
    assert failed.status_code == 503
    assert failed.get_json() == {'status': 'not_ready', 'failed': ['data_directory']}
    assert client.get('/ready').status_code == 200
    assert client.get('/ready').status_code == 200
    assert probes == [1, 1]


def test_cached_write_probe_does_not_hide_runtime_or_database_state(
    app, client, monkeypatch,
):
    from app import health
    from app.models import db

    monkeypatch.setattr(health, 'time', SimpleNamespace(monotonic=lambda: 1000.0))
    assert client.get('/ready').status_code == 200

    lifecycle = app.extensions['runtime_lifecycle']
    accepting = lifecycle.accepting_work
    monkeypatch.setattr(lifecycle, 'accepting_work', lambda: False)
    assert client.get('/ready').get_json()['failed'] == ['runtime']
    monkeypatch.setattr(lifecycle, 'accepting_work', accepting)

    def fail_database_probe(_statement):
        raise RuntimeError('database unavailable')

    monkeypatch.setattr(db.session, 'execute', fail_database_probe)
    assert client.get('/ready').get_json()['failed'] == ['database']
