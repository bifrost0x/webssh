"""Preflight SFTP v3 metadata before permissive dependency decoding."""

import struct

from paramiko.sftp import CMD_ATTRS, CMD_NAME, SFTPError

import config


class _MetadataReader:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def take(self, size):
        if size > len(self.data) - self.offset:
            raise SFTPError('Malformed SFTP metadata')
        self.offset += size

    def integer(self):
        self.take(4)
        return struct.unpack_from('>I', self.data, self.offset - 4)[0]

    def string(self):
        size = self.integer()
        if size > config.REMOTE_FILENAME_MAX_BYTES:
            raise SFTPError('SFTP metadata string exceeds byte limit')
        self.take(size)
        return size

    def attributes(self):
        flags = self.integer()
        if flags & ~0x8000000F:
            raise SFTPError('Unsupported SFTP attribute flags')
        for flag, size in ((1, 8), (2, 8), (4, 4), (8, 8)):
            if flags & flag:
                self.take(size)
        if flags & 0x80000000:
            count = self.integer()
            # Each extension needs at least two actual uint32 string lengths.
            if count > 16 or count > (len(self.data) - self.offset) // 8:
                raise SFTPError('SFTP attribute extension count exceeds limit')
            total = 0
            for _ in range(count):
                total += self.string() + self.string()
                if total > min(config.REMOTE_LISTING_MAX_METADATA_BYTES, 64 * 1024):
                    raise SFTPError('SFTP attribute extensions exceed byte limit')


def validate_metadata_packet(command, data):
    """Check actual bytes, including every NAME entry, without changing them."""
    if command not in (CMD_ATTRS, CMD_NAME):
        return
    reader = _MetadataReader(data)
    reader.take(4)  # Request ID, also required for an empty NAME response.
    if command == CMD_ATTRS:
        reader.attributes()
    else:
        count = reader.integer()
        # A NAME entry requires two string lengths and the attribute flags.
        if count > (len(data) - reader.offset) // 12:
            raise SFTPError('SFTP name count exceeds packet contents')
        for _ in range(count):
            reader.string()
            reader.string()
            reader.attributes()
    if reader.offset != len(data):
        raise SFTPError('Trailing SFTP metadata')
