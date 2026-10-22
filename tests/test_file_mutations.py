"""Boundary tests for explicit, non-overwriting file mutations."""

import errno
import stat
from types import SimpleNamespace

import pytest
from flask import Flask


@pytest.mark.parametrize('name', [None, True, 1, '', '.', '..', '../x', 'a/b', 'a\\b', '\x00', 'a\n', '\x7f', 'é' * 128, '\ud800'])
def test_creation_rejects_invalid_leaf_names(name):
    from app.file_mutations import FileMutationError, validate_leaf
    with pytest.raises(FileMutationError) as failure:
        validate_leaf(name)
    assert failure.value.code == 'INVALID_REQUEST'


@pytest.mark.parametrize('name', ['.env', '-script.sh', 'a b', 'Überblick.txt', 'é' * 127])
def test_creation_preserves_valid_names(name):
    from app.file_mutations import validate_leaf
    assert validate_leaf(name) == name


@pytest.mark.parametrize('path', ['/', '//', '//.', '///', '.', '/a/..', '/./'])
def test_chmod_cannot_address_the_remote_root_through_aliases(path):
    from app.file_mutations import FileMutationError, validate_path
    with pytest.raises(FileMutationError):
        validate_path(path, mutation=True)


@pytest.mark.parametrize('mode', [True, 600, None, '0600', '888', 'u+x', '777\n', '６００', ''])
def test_mode_is_exactly_three_ascii_octal_digits(mode):
    from app.file_mutations import FileMutationError, parse_mode
    with pytest.raises(FileMutationError):
        parse_mode(mode)


def test_mode_round_trip_and_permission_snapshot():
    from app.file_mutations import parse_mode, permission_snapshot
    assert parse_mode('000') == 0
    assert parse_mode('750') == 0o750
    info = SimpleNamespace(st_mode=stat.S_IFREG | 0o640, st_size=3, st_mtime=1, st_uid=7, st_gid=8)
    result = permission_snapshot(info)
    assert result['mode'] == '640'
    assert result['object_type'] == 'file'
    assert result['special_bits'] == 0


@pytest.mark.parametrize('mode', [None, True, stat.S_IFLNK | 0o777, stat.S_IFIFO | 0o600])
def test_unsupported_object_metadata_never_becomes_editable(mode):
    from app.file_mutations import FileMutationError, permission_snapshot
    with pytest.raises(FileMutationError):
        permission_snapshot(SimpleNamespace(st_mode=mode, st_size=0, st_mtime=1))


def test_metadata_token_is_bound_to_user_source_path_snapshot_and_expiry():
    from app.file_mutations import FileMutationError, issue_metadata_token, verify_metadata_token
    app = Flask(__name__)
    app.secret_key = 'unit-test-secret'
    snapshot = {'mode': '600', 'object_type': 'file', 'special_bits': 0, 'size': 0, 'modified': 1}
    with app.app_context():
        token = issue_metadata_token('7', 'sftp-session:a', '/a', snapshot, now=100)
        assert len(token) <= 512
        verify_metadata_token(token, '7', 'sftp-session:a', '/a', snapshot, now=159)
        for user, source, path, value, clock in [
            ('8', 'sftp-session:a', '/a', snapshot, 100),
            ('7', 'sftp-session:b', '/a', snapshot, 100),
            ('7', 'sftp-session:a', '/b', snapshot, 100),
            ('7', 'sftp-session:a', '/a', {**snapshot, 'mode': '644'}, 100),
            ('7', 'sftp-session:a', '/a', snapshot, 161),
        ]:
            with pytest.raises(FileMutationError):
                verify_metadata_token(token, user, source, path, value, now=clock)
        with pytest.raises(FileMutationError):
            verify_metadata_token(token + 'x', '7', 'sftp-session:a', '/a', snapshot, now=101)


@pytest.mark.parametrize('error, code', [
    (PermissionError('private'), 'PERMISSION_DENIED'),
    (FileExistsError('private'), 'CONFLICT'),
    (FileNotFoundError('private'), 'NOT_FOUND'),
    (OSError(errno.EOPNOTSUPP, 'private'), 'UNSUPPORTED_OPERATION'),
    (TimeoutError('private'), 'TIMEOUT'),
    (OSError('private'), 'OPERATION_FAILED'),
])
def test_mutation_errors_never_reflect_server_messages(error, code):
    from app.file_mutations import mutation_failure
    failure = mutation_failure(error)
    assert failure.code == code
    assert 'private' not in str(failure)


def test_create_service_checks_capability_before_backend():
    from app.file_service import FileService
    from app.file_sources import FileSourceUnavailable
    service = FileService(SimpleNamespace(resolve=lambda *_: SimpleNamespace(descriptor=SimpleNamespace(capabilities=()))))
    with pytest.raises(FileSourceUnavailable):
        service.create_file('sftp-session:a', user_id=7, parent_path='/', name='x')


def test_chmod_policy_is_checked_even_with_forged_backend_capability(monkeypatch):
    import config
    from app.file_mutations import FileMutationError
    from app.file_service import FileService
    monkeypatch.setattr(config, 'SFTP_CHMOD_ENABLED', False)
    service = FileService(SimpleNamespace(resolve=lambda *_: pytest.fail('disabled chmod resolved a source')))
    with pytest.raises(FileMutationError) as failure:
        service.get_file_permissions('sftp-session:a', user_id=7, path='/x')
    assert failure.value.code == 'UNSUPPORTED_OPERATION'
