import io

import pytest


def test_reader_lease_binds_validated_metadata_to_the_exact_reader():
    """Dropping the opened reader from the lease recreates path TOCTOU."""
    from app.file_backend import FileReaderLease

    reader = io.BytesIO(b'bound-object')
    lease = FileReaderLease(
        reader=reader,
        size=12,
        mode=0o100600,
        modified=123.5,
        is_dir=False,
        is_symlink=False,
    )

    assert lease.reader is reader
    assert lease.size == 12
    assert lease.mode == 0o100600
    assert lease.modified == 123.5
    assert lease.is_dir is False
    assert lease.is_symlink is False


@pytest.mark.parametrize('size', [True, -1, 1.5, '1'])
def test_reader_lease_rejects_untrusted_sizes(size):
    """Boolean, negative, or coerced sizes can bypass byte ceilings."""
    from app.file_backend import FileReaderLease

    with pytest.raises(ValueError, match='size'):
        FileReaderLease(reader=io.BytesIO(), size=size)


@pytest.mark.parametrize(
    ('overrides', 'message'),
    [
        ({'is_dir': True}, 'directory'),
        ({'is_symlink': True}, 'symbolic'),
        ({'is_dir': 0}, 'is_dir'),
        ({'is_symlink': 0}, 'is_symlink'),
    ],
)
def test_reader_lease_rejects_non_regular_object_metadata(overrides, message):
    """A reader lease must never bless a directory or link-like object."""
    from app.file_backend import FileReaderLease

    with pytest.raises(ValueError, match=message):
        FileReaderLease(reader=io.BytesIO(), size=0, **overrides)


def test_reader_lease_rejects_an_object_without_read():
    """Metadata without its readable handle is not object binding."""
    from app.file_backend import FileReaderLease

    with pytest.raises(ValueError, match='reader'):
        FileReaderLease(reader=object(), size=0)


@pytest.mark.parametrize('mode', [True, -1, '600'])
def test_reader_lease_rejects_invalid_modes(mode):
    from app.file_backend import FileReaderLease

    with pytest.raises(ValueError, match='mode'):
        FileReaderLease(reader=io.BytesIO(), size=0, mode=mode)


@pytest.mark.parametrize('modified', [True, -1, 'now'])
def test_reader_lease_rejects_invalid_modified_values(modified):
    from app.file_backend import FileReaderLease

    with pytest.raises(ValueError, match='modified'):
        FileReaderLease(reader=io.BytesIO(), size=0, modified=modified)
