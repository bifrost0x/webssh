from types import SimpleNamespace

import pytest

from app import socket_events, socket_file_control
from app.file_mutations import FileMutationError
from app.file_sources import FileSourceUnavailable


@pytest.fixture(autouse=True)
def budgets():
    socket_file_control._file_control_budgets.clear()
    yield
    socket_file_control._file_control_budgets.clear()


def test_create_request_is_correlated_and_audited_without_full_paths(monkeypatch):
    emitted, audits = [], []
    user = SimpleNamespace(id=7, username='operator')
    source = SimpleNamespace(source_id='sftp-session:owned')
    monkeypatch.setattr(socket_events, 'emit', lambda event, payload: emitted.append((event, payload)))
    monkeypatch.setattr(socket_events.file_service, 'resolve', lambda *_: source)
    monkeypatch.setattr(socket_events.file_service, 'create_file', lambda *args, **kwargs: {'path': '/private/new', 'size': 0})
    monkeypatch.setattr(socket_events, '_audit_file_source_operation', lambda *_args, **kwargs: audits.append(kwargs))
    socket_events.handle_create_file.__wrapped__({'source_id': source.source_id, 'request_id': 'new:1', 'parent_path': '/private', 'name': 'new'}, current_user=user)
    assert emitted == [('file_created', {'source_id': source.source_id, 'request_id': 'new:1', 'operation': 'create_file', 'path': '/private/new', 'size': 0})]
    assert audits[0]['operation'] == 'create_file'


@pytest.mark.parametrize('error, code', [(FileSourceUnavailable(), 'SOURCE_UNAVAILABLE'), (FileMutationError('OUTCOME_UNKNOWN'), 'OUTCOME_UNKNOWN'), (OSError('token=private'), 'OPERATION_FAILED')])
def test_mutation_failure_is_safe_and_correlated(monkeypatch, error, code):
    emitted = []
    monkeypatch.setattr(socket_events, 'emit', lambda event, payload: emitted.append((event, payload)))
    monkeypatch.setattr(socket_events.file_service, 'resolve', lambda *_: (_ for _ in ()).throw(error))
    socket_events.handle_create_file.__wrapped__({'source_id': 'sftp-session:owned', 'request_id': 'new:1', 'parent_path': '/', 'name': 'new'}, current_user=SimpleNamespace(id=7))
    assert emitted[0][1]['code'] == code
    assert emitted[0][1]['request_id'] == 'new:1'
    assert 'private' not in str(emitted)


@pytest.mark.parametrize('data', [None, [], {'source_id': 'sftp-session:a', 'request_id': 'r', 'parent_path': '/', 'name': '../escape'}, {'source_id': 'sftp-session:a', 'request_id': 'r', 'parent_path': '/' * 5000, 'name': 'new'}])
def test_malformed_mutation_never_reaches_a_backend(monkeypatch, data):
    emitted = []
    monkeypatch.setattr(socket_events, 'emit', lambda *args: emitted.append(args))
    monkeypatch.setattr(socket_events.file_service, 'resolve', lambda *_: pytest.fail('malformed request resolved source'))
    socket_events.handle_create_file.__wrapped__(data, current_user=SimpleNamespace(id=7))
    assert emitted[0][1]['code'] == 'INVALID_REQUEST'


def test_disabled_chmod_rejects_even_direct_socket_request(monkeypatch):
    import config
    monkeypatch.setattr(config, 'SFTP_CHMOD_ENABLED', False)
    emitted = []
    monkeypatch.setattr(socket_events, 'emit', lambda *args: emitted.append(args))
    monkeypatch.setattr(socket_events.file_service, 'resolve', lambda *_: pytest.fail('disabled chmod resolved source'))
    socket_events.handle_set_file_permissions.__wrapped__({'source_id': 'sftp-session:a', 'request_id': 'r', 'path': '/file', 'mode': '777', 'expected_metadata': 'forged'}, current_user=SimpleNamespace(id=7))
    assert emitted[0][1]['code'] == 'UNSUPPORTED_OPERATION'


@pytest.mark.parametrize('handler', ['handle_create_file', 'handle_get_file_permissions', 'handle_set_file_permissions'])
def test_exhausted_control_budget_prevents_source_lookup(monkeypatch, handler):
    emitted = []
    monkeypatch.setattr(socket_events, 'emit', lambda *args: emitted.append(args))
    monkeypatch.setattr(socket_file_control, '_consume_file_control_budget', lambda *_args, **_kwargs: False)
    monkeypatch.setattr(socket_events.file_service, 'resolve', lambda *_: pytest.fail('budget exhausted before source lookup'))
    getattr(socket_events, handler).__wrapped__({
        'source_id': 'sftp-session:a', 'request_id': 'r', 'parent_path': '/',
        'name': 'new', 'path': '/file', 'mode': '600', 'expected_metadata': 'forged',
    }, current_user=SimpleNamespace(id=7))
    assert emitted[0][1]['code'] == 'INVALID_REQUEST'
