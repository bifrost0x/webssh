"""Thin FileBackend adapter over the established SFTP implementation."""

from contextlib import contextmanager
import errno
import posixpath
import secrets
import stat as stat_module

import config

from . import sftp_handler
from .file_backend import FileWriteOutcome


class SFTPBackend:
    """Translate resolved sources to the existing opaque SFTP handle API."""

    def normalize_path(self, path):
        return sftp_handler.sanitize_path(path)

    def list_directory(self, source, path):
        return sftp_handler.list_directory(source.handle_id, path)

    def stat_or_raise(self, source, path, *, follow_links=False):
        if follow_links:
            result, error = sftp_handler.get_file_stat(source.handle_id, path)
            if error:
                raise sftp_handler.SFTPOperationError(error)
            return result

        safe_path = self.normalize_path(path)
        if safe_path is None:
            raise sftp_handler.SFTPOperationError('invalid remote path')
        with sftp_handler.sftp_session(source.handle_id) as (sftp, _source_type):
            file_stat = sftp.lstat(safe_path)
        return {
            'name': posixpath.basename(safe_path),
            'path': safe_path,
            'size': file_stat.st_size,
            'mode': file_stat.st_mode,
            'is_dir': stat_module.S_ISDIR(file_stat.st_mode),
            'is_symlink': stat_module.S_ISLNK(file_stat.st_mode),
            'modified': file_stat.st_mtime,
            'permissions': oct(file_stat.st_mode)[-3:],
        }

    def stat(self, source, path, *, follow_links=False):
        try:
            return self.stat_or_raise(
                source, path, follow_links=follow_links
            ), None
        except sftp_handler.SFTPOperationError as exc:
            return None, str(exc)
        except FileNotFoundError:
            return None, 'File not found'
        except Exception as exc:
            return None, str(exc)

    def mkdir_or_raise(self, source, path):
        safe_path = self.normalize_path(path)
        if safe_path is None:
            raise sftp_handler.SFTPOperationError('invalid remote path')
        with sftp_handler.sftp_session(source.handle_id) as (sftp, _source_type):
            sftp.mkdir(safe_path)

    def mkdir(self, source, path):
        return sftp_handler.create_directory(source.handle_id, path)

    def rename(self, source, old_path, new_path, *, replace=False):
        if replace:
            return False, 'Atomic replacement is unavailable'
        return sftp_handler.rename_item(source.handle_id, old_path, new_path)

    def delete(
        self,
        source,
        path,
        *,
        recursive,
        budget,
        cancel_event,
    ):
        if cancel_event is not None and cancel_event.is_set():
            return False, 'Operation cancelled'
        if recursive:
            return sftp_handler.delete_directory_recursive(
                source.handle_id,
                path,
                member_budget=budget,
                cancel_event=cancel_event,
            )

        safe_path = self.normalize_path(path)
        if safe_path is None:
            return False, 'Invalid path'
        try:
            with sftp_handler.sftp_session(source.handle_id) as (sftp, _source_type):
                file_stat = sftp.lstat(safe_path)
                if stat_module.S_ISDIR(file_stat.st_mode):
                    sftp.rmdir(safe_path)
                else:
                    sftp.remove(safe_path)
            return True, None
        except Exception as exc:
            return False, str(exc)

    @contextmanager
    def open_reader(self, source, path, *, io_lane='control'):
        with sftp_handler.open_bound_reader(
            source.handle_id,
            path,
            io_lane=io_lane,
        ) as lease:
            yield lease

    @contextmanager
    def open_atomic_writer(
        self,
        source,
        path,
        *,
        replace,
        cancel_event,
        io_lane='control',
    ):
        safe_path = self.normalize_path(path)
        if safe_path is None:
            raise sftp_handler.SFTPOperationError('invalid remote path')
        temporary_path = f'{safe_path}.webssh-write-{secrets.token_hex(12)}.tmp'
        with sftp_handler.sftp_session(
            source.handle_id, io_lane=io_lane
        ) as (sftp, _source_type):
            try:
                with sftp.file(temporary_path, 'wb') as remote_file:
                    yield remote_file
                if cancel_event is not None and cancel_event.is_set():
                    raise sftp_handler.TransferCancelled()
                if replace:
                    try:
                        sftp.posix_rename(temporary_path, safe_path)
                    except (AttributeError, IOError, OSError) as exc:
                        raise sftp_handler.SFTPOperationError(
                            'atomic replacement is unavailable'
                        ) from exc
                else:
                    try:
                        sftp.lstat(safe_path)
                    except FileNotFoundError:
                        pass
                    except OSError as exc:
                        if exc.errno != errno.ENOENT:
                            raise
                    else:
                        raise FileExistsError('destination already exists')
                    sftp.rename(temporary_path, safe_path)
            except Exception:
                try:
                    sftp.remove(temporary_path)
                except Exception:
                    pass
                raise

    def iter_tree(
        self,
        source,
        path,
        *,
        budget,
        cancel_event,
        follow_links=False,
        io_lane='control',
    ):
        if follow_links:
            raise sftp_handler.SFTPOperationError('following links is unavailable')
        safe_path = self.normalize_path(path)
        if safe_path is None:
            raise sftp_handler.SFTPOperationError('invalid remote path')
        member_budget = budget or sftp_handler._TransferMemberBudget(
            config.MAX_TRANSFER_MEMBERS
        )

        def iterate():
            with sftp_handler.sftp_session(
                source.handle_id, io_lane=io_lane
            ) as (sftp, _source_type):
                def walk(directory, depth=0):
                    if depth > 50:
                        raise sftp_handler.SFTPOperationError(
                            'maximum directory depth exceeded'
                        )
                    if sftp_handler._is_cancelled(cancel_event):
                        raise sftp_handler.TransferCancelled()
                    with sftp_handler._directory_entries(sftp, directory) as entries:
                        for entry in entries:
                            member_budget.consume()
                            if sftp_handler._is_cancelled(cancel_event):
                                raise sftp_handler.TransferCancelled()
                            name = entry.filename
                            if not sftp_handler._is_safe_transfer_entry_name(name):
                                raise sftp_handler.SFTPOperationError(
                                    'unsafe transfer entry name'
                                )
                            entry_path = posixpath.join(directory, name)
                            entry_stat = sftp.lstat(entry_path)
                            is_link = stat_module.S_ISLNK(entry_stat.st_mode)
                            is_directory = stat_module.S_ISDIR(entry_stat.st_mode)
                            yield {
                                'name': name,
                                'path': entry_path,
                                'size': getattr(entry_stat, 'st_size', 0) or 0,
                                'mode': entry_stat.st_mode,
                                'is_dir': is_directory,
                                'is_symlink': is_link,
                            }
                            if is_directory and not is_link:
                                yield from walk(entry_path, depth + 1)

                yield from walk(safe_path)

        return iterate()

    def get_home_directory(self, source):
        return sftp_handler.get_home_directory(source.handle_id)

    def check_exists(self, source, path):
        try:
            return self.check_exists_or_raise(source, path), None
        except Exception as exc:
            return None, str(exc)

    def check_exists_or_raise(self, source, path):
        safe_path = self.normalize_path(path)
        if safe_path is None:
            raise sftp_handler.SFTPOperationError('invalid remote path')
        try:
            file_stat = self.stat_or_raise(
                source, safe_path, follow_links=False
            )
        except FileNotFoundError:
            return {'exists': False, 'is_dir': False, 'size': 0}
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                return {'exists': False, 'is_dir': False, 'size': 0}
            raise
        return {
            'exists': True,
            'is_dir': file_stat['is_dir'],
            'size': file_stat['size'],
        }

    def get_file_stat(self, source, path):
        return sftp_handler.get_file_stat(source.handle_id, path)

    def read_file_preview(
        self,
        source,
        path,
        *,
        max_bytes,
        offset,
        tail_lines,
    ):
        return sftp_handler.read_file_preview(
            session_id=source.handle_id,
            path=path,
            max_bytes=max_bytes,
            offset=offset,
            tail_lines=tail_lines,
        )

    def read_file_for_edit(self, source, path):
        return sftp_handler.read_file_for_edit(
            session_id=source.handle_id,
            path=path,
        )

    def read_binary_preview(self, source, path, *, max_size):
        from . import binary_transfer

        return binary_transfer.handle_binary_download(
            session_id=source.handle_id,
            remote_path=path,
            socketio_instance=None,
            max_size=max_size,
        )

    def write_file_text(
        self,
        source,
        path,
        content,
        *,
        encoding,
        newline,
        allow_non_atomic=False,
        expected_revision=None,
        replace_strategy='atomic',
    ):
        del allow_non_atomic
        if replace_strategy != 'atomic':
            return FileWriteOutcome(
                success=False,
                error='Invalid replacement strategy',
            )
        return sftp_handler.write_file_text(
            session_id=source.handle_id,
            path=path,
            content_str=content,
            encoding=encoding,
            newline=newline,
            expected_revision=expected_revision,
        )
