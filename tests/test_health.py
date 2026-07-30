def test_health_reports_process_liveness(client):
    response = client.get('/health')

    assert response.status_code == 200
    assert response.get_json() == {'status': 'ok'}


def test_ready_reports_success_when_dependencies_are_available(client):
    response = client.get('/ready')

    assert response.status_code == 200
    assert response.get_json() == {'status': 'ready'}


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
