"""Reproducible tar of the generated DATA_DIR, and safe extraction.

Members are sorted, carry the run's start time as mtime, uid/gid 0 and no
owner names; file modes are kept. Empty directories are included, which a
git checkout would otherwise drop.
"""

import tarfile
from pathlib import Path

from . import runtime

PREFIX = 'data'


def _info(path, name):
    info = tarfile.TarInfo(name)
    stat = path.lstat()
    info.mode = stat.st_mode & 0o7777
    info.mtime = int(runtime.START.timestamp())
    info.uid = info.gid = 0
    info.uname = info.gname = ''
    if path.is_dir():
        info.type = tarfile.DIRTYPE
    else:
        info.size = stat.st_size
    return info


def members(data_dir):
    data_dir = Path(data_dir)
    paths = sorted(data_dir.rglob('*'), key=lambda p: p.relative_to(data_dir).as_posix())
    yield data_dir, PREFIX
    for path in paths:
        if path.is_symlink():
            raise ValueError(f'symbolic link in data directory: {path}')
        yield path, f'{PREFIX}/{path.relative_to(data_dir).as_posix()}'


def pack_data_dir(data_dir, archive):
    with tarfile.open(archive, 'w', format=tarfile.USTAR_FORMAT) as tar:
        for path, name in members(data_dir):
            info = _info(path, name)
            if info.isdir():
                tar.addfile(info)
            else:
                with path.open('rb') as handle:
                    tar.addfile(info, handle)


def extract_data_dir(archive, destination):
    """Extract to ``destination/data`` with the stdlib "data" filter."""
    with tarfile.open(archive) as tar:
        tar.extractall(destination, filter='data')
    return Path(destination) / PREFIX
