"""Typed errors raised when persistent storage cannot be trusted."""

from pathlib import Path


class StorageCorruptionError(Exception):
    """A storage document exists but cannot be read or validated safely."""

    def __init__(self, path: Path, reason: str):
        self.path = Path(path)
        self.reason = str(reason).replace('\r', ' ').replace('\n', ' ')
        super().__init__(
            f'Storage at {self.path} is corrupt: {self.reason}'
        )
