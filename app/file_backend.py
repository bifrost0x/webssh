"""Protocol-neutral operations exposed by file source backends."""

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from .file_sources import ResolvedFileSource


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

    def mkdir(self, source: 'ResolvedFileSource', path: str) -> Any:
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

    def open_reader(self, source: 'ResolvedFileSource', path: str) -> Any:
        ...

    def open_atomic_writer(
        self,
        source: 'ResolvedFileSource',
        path: str,
        *,
        replace: bool,
        cancel_event: Any,
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
    ) -> Any:
        ...
