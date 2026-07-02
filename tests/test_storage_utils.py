"""Tests for the shared atomic-write / per-key-lock storage helpers."""

import json
import threading


class TestAtomicWriteJson:
    def test_write_and_read_roundtrip(self, tmp_path):
        from app.storage_utils import atomic_write_json
        target = tmp_path / 'data.json'
        atomic_write_json(target, {'a': 1, 'b': [2, 3]})
        assert json.loads(target.read_text(encoding='utf-8')) == {'a': 1, 'b': [2, 3]}

    def test_overwrite_is_atomic_no_tmp_left(self, tmp_path):
        from app.storage_utils import atomic_write_json
        target = tmp_path / 'data.json'
        atomic_write_json(target, {'v': 1})
        atomic_write_json(target, {'v': 2})
        assert json.loads(target.read_text(encoding='utf-8')) == {'v': 2}
        # The temp file must have been renamed away, not left behind.
        assert not (tmp_path / 'data.json.tmp').exists()

    def test_existing_file_survives_when_write_target_valid(self, tmp_path):
        from app.storage_utils import atomic_write_json
        target = tmp_path / 'list.json'
        atomic_write_json(target, [1, 2, 3])
        # A later write replaces content wholesale and stays valid JSON.
        atomic_write_json(target, [])
        assert json.loads(target.read_text(encoding='utf-8')) == []


class TestStorageLock:
    def test_same_key_returns_same_lock(self):
        from app.storage_utils import storage_lock
        assert storage_lock('profiles:1') is storage_lock('profiles:1')

    def test_different_keys_return_different_locks(self):
        from app.storage_utils import storage_lock
        assert storage_lock('profiles:1') is not storage_lock('profiles:2')

    def test_lock_is_usable_as_context_manager(self):
        from app.storage_utils import storage_lock
        lock = storage_lock('ctx-test:1')
        with lock:
            # Same key is held; acquiring non-blockingly must fail while held.
            assert lock.acquire(blocking=False) is False
        # Released after the with-block.
        assert lock.acquire(blocking=False) is True
        lock.release()

    def test_lock_serializes_increment(self):
        from app.storage_utils import storage_lock
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
