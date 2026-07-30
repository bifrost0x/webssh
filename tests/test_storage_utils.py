"""Tests for the shared atomic-write / per-key-lock storage helpers."""

import json
import os
from pathlib import Path
import stat
import threading
from unittest.mock import Mock

import pytest

from app.storage_errors import StorageCorruptionError
from app.storage_utils import (
    atomic_write_bytes,
    atomic_write_json,
    load_json_migrated,
    load_json_strict,
    storage_lock,
)


class TestLoadJsonStrict:
    def test_distinguishes_missing_from_corrupt(self, tmp_path):
        path = tmp_path / 'store.json'
        assert load_json_strict(
            path, list, lambda value: isinstance(value, list)
        ) == []

        path.write_text('{broken', encoding='utf-8')
        with pytest.raises(StorageCorruptionError) as exc_info:
            load_json_strict(path, list, lambda value: isinstance(value, list))

        assert exc_info.value.path == path
        assert exc_info.value.reason == 'invalid JSON'

    def test_missing_file_alone_uses_default_factory(self, tmp_path):
        path = tmp_path / 'store.json'
        default_factory = Mock(return_value={'fresh': True})

        assert load_json_strict(path, default_factory, lambda value: True) == {
            'fresh': True
        }
        default_factory.assert_called_once_with()

    def test_invalid_unicode_is_typed_corruption(self, tmp_path):
        path = tmp_path / 'store.json'
        path.write_bytes(b'\xff')

        with pytest.raises(StorageCorruptionError) as exc_info:
            load_json_strict(path, dict, lambda value: isinstance(value, dict))

        assert exc_info.value.path == path
        assert exc_info.value.reason == 'invalid Unicode'

    def test_schema_validation_failure_is_typed_corruption(self, tmp_path):
        path = tmp_path / 'store.json'
        path.write_text('[]', encoding='utf-8')

        with pytest.raises(StorageCorruptionError) as exc_info:
            load_json_strict(path, dict, lambda value: isinstance(value, dict))

        assert exc_info.value.reason == 'validation failed'

    def test_validator_exception_is_sanitized(self, tmp_path):
        path = tmp_path / 'store.json'
        path.write_text('{}', encoding='utf-8')

        def reject(_value):
            raise ValueError('sensitive validator details\nmust not escape')

        with pytest.raises(StorageCorruptionError) as exc_info:
            load_json_strict(path, dict, reject)

        assert exc_info.value.reason == 'validation failed'
        assert 'sensitive' not in str(exc_info.value)
        assert '\n' not in str(exc_info.value)

    def test_read_io_error_is_typed_corruption_without_using_default(
        self, tmp_path, monkeypatch
    ):
        path = tmp_path / 'store.json'
        path.write_text('{}', encoding='utf-8')
        default_factory = Mock(return_value={})
        original_open = Path.open

        def fail_target_open(self, *args, **kwargs):
            if self == path:
                raise PermissionError('private filesystem detail')
            return original_open(self, *args, **kwargs)

        monkeypatch.setattr(Path, 'open', fail_target_open)

        with pytest.raises(StorageCorruptionError) as exc_info:
            load_json_strict(path, default_factory, lambda value: True)

        assert exc_info.value.reason == 'read failed'
        assert 'private filesystem detail' not in str(exc_info.value)
        default_factory.assert_not_called()

    def test_file_disappearing_during_read_is_corruption_and_closes_handle(
        self, tmp_path, monkeypatch
    ):
        path = tmp_path / 'store.json'
        path.write_text('{}', encoding='utf-8')
        default_factory = Mock(return_value={})

        class DisappearingHandle:
            def __init__(self):
                self.closed = False

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                self.closed = True

            def read(self):
                raise FileNotFoundError('removed after open')

        handle = DisappearingHandle()
        monkeypatch.setattr(Path, 'open', Mock(return_value=handle))

        with pytest.raises(StorageCorruptionError) as exc_info:
            load_json_strict(path, default_factory, lambda value: True)

        assert exc_info.value.path == path
        assert exc_info.value.reason == 'read failed'
        assert handle.closed is True
        default_factory.assert_not_called()

    def test_returns_valid_document_unchanged(self, tmp_path):
        path = tmp_path / 'store.json'
        path.write_text('{"items": [1, 2]}', encoding='utf-8')

        value = load_json_strict(
            path,
            dict,
            lambda candidate: (
                isinstance(candidate, dict)
                and isinstance(candidate.get('items'), list)
            ),
        )

        assert value == {'items': [1, 2]}


class TestAtomicWriteJson:
    def test_write_and_read_roundtrip(self, tmp_path):
        target = tmp_path / 'data.json'
        atomic_write_json(target, {'a': 1, 'b': [2, 3]})
        assert json.loads(target.read_text(encoding='utf-8')) == {'a': 1, 'b': [2, 3]}

    def test_overwrite_is_atomic_no_tmp_left(self, tmp_path):
        target = tmp_path / 'data.json'
        atomic_write_json(target, {'v': 1})
        atomic_write_json(target, {'v': 2})
        assert json.loads(target.read_text(encoding='utf-8')) == {'v': 2}
        # The temp file must have been renamed away, not left behind.
        assert not (tmp_path / 'data.json.tmp').exists()

    def test_existing_file_survives_when_write_target_valid(self, tmp_path):
        target = tmp_path / 'list.json'
        atomic_write_json(target, [1, 2, 3])
        # A later write replaces content wholesale and stays valid JSON.
        atomic_write_json(target, [])
        assert json.loads(target.read_text(encoding='utf-8')) == []

    def test_preserves_indent_argument(self, tmp_path):
        target = tmp_path / 'data.json'
        atomic_write_json(target, {'nested': {'value': 1}}, indent=4)
        assert '\n    "nested"' in target.read_text(encoding='utf-8')

    def test_preserves_destination_on_replace_failure(self, tmp_path, monkeypatch):
        target = tmp_path / 'data.json'
        target.write_text('{"old": true}', encoding='utf-8')
        monkeypatch.setattr(os, 'replace', Mock(side_effect=OSError('blocked')))

        with pytest.raises(OSError, match='blocked'):
            atomic_write_json(target, {'new': True})

        assert target.read_text(encoding='utf-8') == '{"old": true}'
        assert list(tmp_path.iterdir()) == [target]


class TestAtomicWriteBytes:
    @staticmethod
    def _patch_temporary_file(monkeypatch, *, fail_operation=None, calls=None):
        import app.storage_utils as storage_utils

        real_named_temporary_file = storage_utils.tempfile.NamedTemporaryFile

        class InstrumentedTemporaryFile:
            def __init__(self, *args, **kwargs):
                self._handle = real_named_temporary_file(*args, **kwargs)
                self.name = self._handle.name

            def __enter__(self):
                self._handle.__enter__()
                return self

            def __exit__(self, *args):
                return self._handle.__exit__(*args)

            def write(self, payload):
                if calls is not None:
                    calls.append('write')
                if fail_operation == 'write':
                    raise OSError('write failed')
                return self._handle.write(payload)

            def flush(self):
                if calls is not None:
                    calls.append('flush')
                if fail_operation == 'flush':
                    raise OSError('flush failed')
                return self._handle.flush()

            def fileno(self):
                return self._handle.fileno()

        monkeypatch.setattr(
            storage_utils.tempfile,
            'NamedTemporaryFile',
            InstrumentedTemporaryFile,
        )

    def test_preserves_destination_on_replace_failure(self, tmp_path, monkeypatch):
        path = tmp_path / 'secret'
        path.write_bytes(b'old')
        monkeypatch.setattr(os, 'replace', Mock(side_effect=OSError('blocked')))

        with pytest.raises(OSError, match='blocked'):
            atomic_write_bytes(path, b'new')

        assert path.read_bytes() == b'old'
        assert list(tmp_path.iterdir()) == [path]

    @pytest.mark.parametrize('operation', ['write', 'flush'])
    def test_preserves_destination_and_cleans_temp_on_stream_failure(
        self, tmp_path, monkeypatch, operation
    ):
        path = tmp_path / 'secret'
        path.write_bytes(b'old')
        self._patch_temporary_file(
            monkeypatch,
            fail_operation=operation,
        )

        with pytest.raises(OSError, match=f'{operation} failed'):
            atomic_write_bytes(path, b'new')

        assert path.read_bytes() == b'old'
        assert list(tmp_path.iterdir()) == [path]

    def test_preserves_destination_and_cleans_temp_on_chmod_failure(
        self, tmp_path, monkeypatch
    ):
        path = tmp_path / 'secret'
        path.write_bytes(b'old')
        monkeypatch.setattr(os, 'chmod', Mock(side_effect=OSError('chmod failed')))

        with pytest.raises(OSError, match='chmod failed'):
            atomic_write_bytes(path, b'new')

        assert path.read_bytes() == b'old'
        assert list(tmp_path.iterdir()) == [path]

    def test_temporary_file_is_created_in_destination_parent(
        self, tmp_path, monkeypatch
    ):
        path = tmp_path / 'nested' / 'secret'
        path.parent.mkdir()
        real_replace = os.replace
        observed = {}

        def inspect_replace(source, destination):
            observed['source'] = Path(source)
            observed['destination'] = Path(destination)
            assert observed['source'].parent == path.parent
            real_replace(source, destination)

        monkeypatch.setattr(os, 'replace', inspect_replace)

        atomic_write_bytes(path, b'payload')

        assert observed['destination'] == path
        assert path.read_bytes() == b'payload'

    def test_flushes_and_fsyncs_before_replace(self, tmp_path, monkeypatch):
        import app.storage_utils as storage_utils

        path = tmp_path / 'secret'
        calls = []
        self._patch_temporary_file(monkeypatch, calls=calls)
        real_fsync = os.fsync
        real_chmod = os.chmod
        real_replace = os.replace

        def record_fsync(fd):
            calls.append('fsync')
            return real_fsync(fd)

        def record_chmod(target, mode):
            calls.append('chmod')
            return real_chmod(target, mode)

        def record_replace(source, destination):
            calls.append('replace')
            return real_replace(source, destination)

        def record_directory_fsync(target):
            assert Path(target) == path
            calls.append('directory_fsync')

        monkeypatch.setattr(os, 'fsync', record_fsync)
        monkeypatch.setattr(os, 'chmod', record_chmod)
        monkeypatch.setattr(os, 'replace', record_replace)
        monkeypatch.setattr(
            storage_utils,
            'fsync_parent_directory',
            record_directory_fsync,
            raising=False,
        )

        atomic_write_bytes(path, b'payload')

        assert calls == [
            'write',
            'flush',
            'fsync',
            'chmod',
            'replace',
            'directory_fsync',
        ]

    def test_directory_fsync_failure_is_surfaced_after_active_replace(
        self, tmp_path, monkeypatch
    ):
        import app.storage_utils as storage_utils

        path = tmp_path / 'secret'
        path.write_bytes(b'old')
        monkeypatch.setattr(
            storage_utils,
            'fsync_parent_directory',
            Mock(side_effect=OSError('directory sync failed')),
            raising=False,
        )

        with pytest.raises(OSError, match='directory sync failed'):
            atomic_write_bytes(path, b'new')

        # os.replace has already committed the new directory entry. The error
        # means durability is unknown, not that the old file is still active.
        assert path.read_bytes() == b'new'
        assert list(tmp_path.iterdir()) == [path]

    def test_preserves_destination_and_cleans_temp_on_fsync_failure(
        self, tmp_path, monkeypatch
    ):
        path = tmp_path / 'secret'
        path.write_bytes(b'old')
        monkeypatch.setattr(os, 'fsync', Mock(side_effect=OSError('disk failed')))

        with pytest.raises(OSError, match='disk failed'):
            atomic_write_bytes(path, b'new')

        assert path.read_bytes() == b'old'
        assert list(tmp_path.iterdir()) == [path]

    def test_applies_requested_mode_portably(self, tmp_path):
        path = tmp_path / 'secret'
        atomic_write_bytes(path, b'payload', mode=0o600)

        actual_mode = stat.S_IMODE(path.stat().st_mode)
        if os.name == 'nt':
            assert actual_mode & stat.S_IWUSR
        else:
            assert actual_mode == 0o600


class TestLoadJsonMigrated:
    @staticmethod
    def _valid_settings(value):
        return (
            isinstance(value, dict)
            and value.get('schema_version') == 2
        )

    def test_only_missing_open_uses_migrated_default(
        self, tmp_path, monkeypatch
    ):
        path = tmp_path / 'settings.json'
        default_factory = Mock(return_value={'theme': 'glass'})
        real_exists = Path.exists

        def reject_exists(candidate):
            if candidate == path:
                raise AssertionError(
                    'Path.exists must not be used before opening'
                )
            return real_exists(candidate)

        monkeypatch.setattr(Path, 'exists', reject_exists)

        assert load_json_migrated(
            path,
            'settings',
            default_factory,
            self._valid_settings,
        ) == {
            'schema_version': 2,
            'theme': 'glass',
        }
        default_factory.assert_called_once_with()

    @pytest.mark.parametrize(
        'read_error',
        [
            PermissionError('private filesystem detail'),
            OSError('symlink loop or other lookup failure'),
        ],
    )
    def test_non_missing_read_errors_fail_closed_without_default_or_write(
        self, tmp_path, monkeypatch, read_error
    ):
        import app.storage_migrations as storage_migrations

        path = tmp_path / 'settings.json'
        default_factory = Mock(return_value={'theme': 'must-not-be-used'})
        validator = Mock(return_value=True)
        original_open = Path.open

        def fail_target_open(candidate, *args, **kwargs):
            if candidate == path:
                raise read_error
            return original_open(candidate, *args, **kwargs)

        monkeypatch.setattr(Path, 'open', fail_target_open)
        monkeypatch.setattr(
            storage_migrations,
            'backup_before_migration',
            Mock(side_effect=AssertionError('backup must not run')),
        )
        monkeypatch.setattr(
            storage_migrations,
            'atomic_write_json',
            Mock(side_effect=AssertionError('write must not run')),
        )

        with pytest.raises(StorageCorruptionError) as exc_info:
            load_json_migrated(
                path,
                'settings',
                default_factory,
                validator,
            )

        assert exc_info.value.reason == 'read failed'
        assert 'private filesystem detail' not in str(exc_info.value)
        assert 'symlink loop' not in str(exc_info.value)
        default_factory.assert_not_called()
        validator.assert_not_called()
        storage_migrations.backup_before_migration.assert_not_called()
        storage_migrations.atomic_write_json.assert_not_called()

    def test_file_disappearing_during_read_is_not_treated_as_missing(
        self, tmp_path, monkeypatch
    ):
        import app.storage_migrations as storage_migrations

        path = tmp_path / 'settings.json'
        default_factory = Mock(return_value={'theme': 'must-not-be-used'})
        validator = Mock(return_value=True)
        original_open = Path.open

        class DisappearingHandle:
            def __init__(self):
                self.enter_calls = 0
                self.read_calls = 0
                self.exit_calls = 0
                self.closed = False

            def __enter__(self):
                self.enter_calls += 1
                return self

            def __exit__(self, *_args):
                self.exit_calls += 1
                self.closed = True

            def read(self):
                self.read_calls += 1
                raise FileNotFoundError('removed after successful open')

        handle = DisappearingHandle()

        def open_target(candidate, *args, **kwargs):
            if candidate == path:
                mode = args[0] if args else kwargs.get('mode')
                assert mode == 'rb'
                return handle
            return original_open(candidate, *args, **kwargs)

        monkeypatch.setattr(Path, 'open', open_target)
        monkeypatch.setattr(
            storage_migrations,
            'backup_before_migration',
            Mock(side_effect=AssertionError('backup must not run')),
        )
        monkeypatch.setattr(
            storage_migrations,
            'atomic_write_json',
            Mock(side_effect=AssertionError('write must not run')),
        )

        with pytest.raises(StorageCorruptionError) as exc_info:
            load_json_migrated(
                path,
                'settings',
                default_factory,
                validator,
            )

        assert exc_info.value.reason == 'read failed'
        assert 'removed after successful open' not in str(exc_info.value)
        assert handle.enter_calls == 1
        assert handle.read_calls == 1
        assert handle.exit_calls == 1
        assert handle.closed is True
        default_factory.assert_not_called()
        validator.assert_not_called()
        storage_migrations.backup_before_migration.assert_not_called()
        storage_migrations.atomic_write_json.assert_not_called()


class TestStorageLock:
    def test_same_key_returns_same_lock(self):
        assert storage_lock('profiles:1') is storage_lock('profiles:1')

    def test_different_keys_return_different_locks(self):
        assert storage_lock('profiles:1') is not storage_lock('profiles:2')

    def test_lock_is_usable_as_context_manager(self):
        lock = storage_lock('ctx-test:1')
        with lock:
            # Same key is held; acquiring non-blockingly must fail while held.
            assert lock.acquire(blocking=False) is False
        # Released after the with-block.
        assert lock.acquire(blocking=False) is True
        lock.release()

    def test_lock_serializes_increment(self):
        state = {'n': 0}

        def worker():
            for _ in range(1000):
                with storage_lock('counter:1'):
                    state['n'] += 1

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert state['n'] == 4000

    def test_four_concurrent_load_modify_save_users_do_not_lose_updates(
        self, tmp_path
    ):
        path = tmp_path / 'counter.json'
        atomic_write_json(path, {'n': 0})

        def worker():
            for _ in range(25):
                with storage_lock(f'counter-file:{path}'):
                    current = load_json_strict(
                        path,
                        dict,
                        lambda value: (
                            isinstance(value, dict)
                            and isinstance(value.get('n'), int)
                        ),
                    )
                    current['n'] += 1
                    atomic_write_json(path, current)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert json.loads(path.read_text(encoding='utf-8')) == {'n': 100}


def test_safe_reference_name_bounds_and_sanitizes_display_text():
    from app.storage_utils import safe_reference_name

    assert safe_reference_name(None) == ""
    assert safe_reference_name("ok\x00name") == "ok\ufffdname"
    assert safe_reference_name("x" * 140) == "x" * 128
