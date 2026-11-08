from contextlib import contextmanager
from threading import Event

import pytest

from tests.test_remote_transfer import _Backend, _source


def test_premature_eof_preserves_existing_destination():
    from app.file_backend import FileReaderLease, FileSourceChanged
    from app.remote_transfer import TransferBudget, copy_remote_entry

    class TruncatedSource(_Backend):
        @contextmanager
        def open_reader(self, *args, **kwargs):
            with super().open_reader(*args, **kwargs) as lease:
                yield FileReaderLease(reader=lease.reader, size=10)

    source = TruncatedSource({'/source': b'abc'})
    destination = _Backend({'/destination': b'keep original'})
    with pytest.raises(FileSourceChanged):
        copy_remote_entry(_source('sftp', source), '/source',
                          _source('smb', destination), '/destination',
                          conflict_policy='replace',
                          budget=TransferBudget(max_bytes=100, max_members=2),
                          cancel_event=Event(), progress=None, chunk_size=2)
    assert destination.files['/destination'] == b'keep original'
    assert destination.commits == []
