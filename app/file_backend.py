"""Protocol-neutral operations exposed by file source backends."""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from .file_sources import ResolvedFileSource


_WRITE_ERROR_CODES = frozenset({
    'EDIT_CONFLICT',
    'SMB_RECOVERABLE_REPLACE_REQUIRED',
    'SMB_RECOVERABLE_REPLACE_FAILED',
    'SMB_RECOVERY_REQUIRED',
})
_WRITE_WARNING_CODES = frozenset({
    'SMB_RECOVERY_BACKUP_RETAINED',
})


@dataclass(frozen=True, slots=True)
class FileReaderLease:
    """One readable remote object and metadata obtained from that handle."""

    reader: Any
    size: int
    mode: int | None = None
    modified: int | float | None = None
    is_dir: bool = False
    is_symlink: bool = False

    def __post_init__(self):
        if not callable(getattr(self.reader, 'read', None)):
            raise ValueError('reader must expose read')
        if type(self.size) is not int or self.size < 0:
            raise ValueError('size must be a non-negative integer')
        if self.mode is not None and (
            type(self.mode) is not int or self.mode < 0
        ):
            raise ValueError('mode must be a non-negative integer or None')
        if self.modified is not None and (
            isinstance(self.modified, bool)
            or not isinstance(self.modified, (int, float))
            or self.modified < 0
        ):
            raise ValueError('modified must be non-negative or None')
        if type(self.is_dir) is not bool:
            raise ValueError('is_dir must be boolean')
        if type(self.is_symlink) is not bool:
            raise ValueError('is_symlink must be boolean')
        if self.is_dir:
            raise ValueError('reader lease cannot represent a directory')
        if self.is_symlink:
            raise ValueError('reader lease cannot represent a symbolic link')


@dataclass(frozen=True, slots=True)
class FileWriteOutcome:
    """Validated result of an editor save without backend exception leakage."""

    success: bool
    error: str | None = None
    code: str | None = None
    warning_code: str | None = None
    recovery_leaves: tuple[str, ...] = ()
    revision: str | None = None

    def __post_init__(self):
        if not isinstance(self.success, bool):
            raise ValueError('success must be boolean')
        if self.success and self.error is not None:
            raise ValueError('successful writes cannot carry an error')
        if not self.success and self.warning_code is not None:
            raise ValueError('failed writes cannot carry a warning')
        if self.code is not None and self.code not in _WRITE_ERROR_CODES:
            raise ValueError('invalid write error code')
        if (
            self.warning_code is not None
            and self.warning_code not in _WRITE_WARNING_CODES
        ):
            raise ValueError('invalid write warning code')
        if self.success and self.code is not None:
            raise ValueError('successful writes cannot carry an error code')
        if self.error is not None and (
            not isinstance(self.error, str) or not self.error or len(self.error) > 512
        ):
            raise ValueError('invalid write error')
        if not isinstance(self.recovery_leaves, tuple):
            raise ValueError('recovery leaves must be a tuple')
        for leaf in self.recovery_leaves:
            if (
                not isinstance(leaf, str)
                or not leaf
                or len(leaf) > 255
                or leaf in {'.', '..'}
                or '/' in leaf
                or '\\' in leaf
                or '\x00' in leaf
            ):
                raise ValueError('invalid recovery leaf')
        if self.revision is not None and (
            not isinstance(self.revision, str)
            or not 1 <= len(self.revision) <= 128
            or not self.revision.isascii()
            or any(not (character.isalnum() or character in '-_.')
                   for character in self.revision)
        ):
            raise ValueError('invalid write revision')


@runtime_checkable
class FileBackend(Protocol):
    """Small filesystem contract shared by SFTP and future backends."""

    def normalize_path(self, path: str) -> str:
        ...

    def list_directory(self, source: 'ResolvedFileSource', path: str) -> Any:
        ...

    def stat(
        self,
        source: 'ResolvedFileSource',
        path: str,
        *,
        follow_links: bool = False,
    ) -> Any:
        ...

    def stat_or_raise(
        self,
        source: 'ResolvedFileSource',
        path: str,
        *,
        follow_links: bool = False,
    ) -> Any:
        ...

    def mkdir(self, source: 'ResolvedFileSource', path: str) -> Any:
        ...

    def mkdir_or_raise(
        self, source: 'ResolvedFileSource', path: str
    ) -> Any:
        ...

    def check_exists_or_raise(
        self, source: 'ResolvedFileSource', path: str
    ) -> Any:
        ...

    def rename(
        self,
        source: 'ResolvedFileSource',
        old_path: str,
        new_path: str,
        *,
        replace: bool = False,
    ) -> Any:
        ...

    def delete(
        self,
        source: 'ResolvedFileSource',
        path: str,
        *,
        recursive: bool,
        budget: Any,
        cancel_event: Any,
    ) -> Any:
        ...

    def open_reader(
        self,
        source: 'ResolvedFileSource',
        path: str,
        *,
        io_lane: str = 'control',
    ) -> FileReaderLease:
        ...

    def open_atomic_writer(
        self,
        source: 'ResolvedFileSource',
        path: str,
        *,
        replace: bool,
        cancel_event: Any,
        io_lane: str = 'control',
    ) -> Any:
        ...

    def iter_tree(
        self,
        source: 'ResolvedFileSource',
        path: str,
        *,
        budget: Any,
        cancel_event: Any,
        follow_links: bool = False,
        io_lane: str = 'control',
    ) -> Any:
        ...
