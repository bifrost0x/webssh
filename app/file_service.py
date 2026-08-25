"""Authorization and capability boundary for all file source operations."""

from .file_backend import FileWriteOutcome
from .file_sources import (
    FileCapability,
    FileSourceKind,
    FileSourceUnavailable,
    file_source_resolver,
)
from .sftp_backend import SFTPBackend
from .smb_backend import smb_backend


class FileService:
    """Resolve a source and authorize one named operation before dispatch."""

    def __init__(self, resolver):
        self.resolver = resolver

    def resolve(self, source_id, user_id, capability):
        source = self.resolver.resolve(source_id, user_id)
        required = FileCapability(capability)
        if required not in source.descriptor.capabilities:
            raise FileSourceUnavailable()
        return source

    @staticmethod
    def normalize_preview_options(*, max_bytes, offset, tail_lines):
        from . import sftp_handler

        return sftp_handler.normalize_file_preview_options(
            max_bytes=max_bytes,
            offset=offset,
            tail_lines=tail_lines,
        )

    def list_directory(self, source_id, *, user_id, path):
        source = self.resolve(source_id, user_id, FileCapability.LIST)
        return source.backend.list_directory(source, path)

    def get_home_directory(self, source_id, *, user_id):
        source = self.resolve(source_id, user_id, FileCapability.LIST)
        return source.backend.get_home_directory(source)

    def check_exists(self, source_id, *, user_id, path):
        source = self.resolve(source_id, user_id, FileCapability.READ)
        return source.backend.check_exists(source, path)

    def get_file_stat(self, source_id, *, user_id, path):
        source = self.resolve(source_id, user_id, FileCapability.READ)
        return source.backend.get_file_stat(source, path)

    def create_directory(self, source_id, *, user_id, path):
        source = self.resolve(source_id, user_id, FileCapability.MKDIR)
        return source.backend.mkdir(source, path)

    def rename(self, source_id, *, user_id, old_path, new_path):
        source = self.resolve(source_id, user_id, FileCapability.RENAME)
        if any(
            not isinstance(path, str)
            or any(segment == '..' for segment in path.split('/'))
            for path in (old_path, new_path)
        ):
            return False, 'Invalid move request'
        safe_old = source.backend.normalize_path(old_path)
        safe_new = source.backend.normalize_path(new_path)
        case_insensitive = source.descriptor.kind == 'smb'
        comparable_old = (
            safe_old.casefold()
            if case_insensitive and isinstance(safe_old, str)
            else safe_old
        )
        comparable_new = (
            safe_new.casefold()
            if case_insensitive and isinstance(safe_new, str)
            else safe_new
        )
        if (
            safe_old is None
            or safe_new is None
            or safe_old in {'', '.', '/'}
            or safe_new in {'', '.'}
            or comparable_old == comparable_new
            or comparable_new.startswith(
                f"{comparable_old.rstrip('/')}/"
            )
        ):
            return False, 'Invalid move request'
        destination, error = source.backend.check_exists(source, safe_new)
        if error:
            return False, error
        if destination and destination.get('exists'):
            return False, 'Destination already exists'
        return source.backend.rename(
            source,
            safe_old,
            safe_new,
            replace=False,
        )

    def delete(self, source_id, *, user_id, path, cancel_event=None):
        self.resolve(source_id, user_id, FileCapability.DELETE)
        source = self.resolve(source_id, user_id, FileCapability.RECURSIVE)
        return source.backend.delete(
            source,
            path,
            recursive=True,
            budget=None,
            cancel_event=cancel_event,
        )

    def read_file_preview(
        self,
        source_id,
        *,
        user_id,
        path,
        max_bytes,
        offset,
        tail_lines,
    ):
        source = self.resolve(source_id, user_id, FileCapability.PREVIEW)
        return source.backend.read_file_preview(
            source,
            path,
            max_bytes=max_bytes,
            offset=offset,
            tail_lines=tail_lines,
        )

    def read_file_for_edit(self, source_id, *, user_id, path):
        source = self.resolve(source_id, user_id, FileCapability.EDIT)
        return source.backend.read_file_for_edit(source, path)

    def read_binary_preview(self, source_id, *, user_id, path, max_size):
        source = self.resolve(source_id, user_id, FileCapability.PREVIEW)
        return source.backend.read_binary_preview(
            source,
            path,
            max_size=max_size,
        )

    def write_file_text(
        self,
        source_id,
        *,
        user_id,
        path,
        content,
        encoding,
        newline,
        allow_non_atomic=False,
        expected_revision=None,
        replace_strategy='atomic',
    ):
        source = self.resolve(source_id, user_id, FileCapability.EDIT)
        result = source.backend.write_file_text(
            source,
            path,
            content,
            encoding=encoding,
            newline=newline,
            allow_non_atomic=allow_non_atomic,
            expected_revision=expected_revision,
            replace_strategy=replace_strategy,
        )
        if isinstance(result, FileWriteOutcome):
            return result
        if (
            isinstance(result, tuple)
            and len(result) == 2
            and isinstance(result[0], bool)
        ):
            success, error = result
            return FileWriteOutcome(
                success=success,
                error=None if success else (error or 'Save failed'),
            )
        return FileWriteOutcome(success=False, error='Save failed')


sftp_backend = SFTPBackend()
file_source_resolver.register_backend(FileSourceKind.SFTP_SESSION, sftp_backend)
file_source_resolver.register_backend(FileSourceKind.SFTP_QUICK, sftp_backend)
file_source_resolver.register_backend(FileSourceKind.SMB_QUICK, smb_backend)
file_service = FileService(file_source_resolver)
