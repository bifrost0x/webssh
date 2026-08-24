"""Immutable, share-confined SMB path values."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re


class SMBPathRejected(ValueError):
    """A share or path cannot be represented safely within one SMB share."""


_INVALID_COMPONENT_CHARACTERS = frozenset('<>:"/\\|?*')
_RESERVED_DEVICE = re.compile(
    r'(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?\Z',
    re.IGNORECASE,
)


def _validate_component(value, *, maximum, allow_dollar=False):
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise SMBPathRejected('Invalid SMB path component')
    if value in {'.', '..'} or value[-1] in {'.', ' '}:
        raise SMBPathRejected('Invalid SMB path component')
    if any(
        ord(character) < 32
        or character in _INVALID_COMPONENT_CHARACTERS
        or (character == '$' and not allow_dollar)
        for character in value
    ):
        raise SMBPathRejected('Invalid SMB path component')
    if _RESERVED_DEVICE.fullmatch(value):
        raise SMBPathRejected('Reserved SMB path component')
    return value


@dataclass(frozen=True)
class SMBShareName:
    value: str

    @classmethod
    def parse(cls, value):
        # Dollar-suffixed shares are administrative/hidden and deliberately
        # outside this feature's contract.
        return cls(_validate_component(value, maximum=80, allow_dollar=False))

    def __str__(self):
        return self.value


@dataclass(frozen=True)
class SMBPath:
    segments: tuple[str, ...]

    @classmethod
    def parse(cls, value):
        if not isinstance(value, str) or not value.startswith('/'):
            raise SMBPathRejected('SMB paths must be share-rooted')
        if value == '/':
            return cls(())
        if len(value) > 4096 or value.endswith('/') or '//' in value:
            raise SMBPathRejected('Invalid SMB path')
        segments = tuple(
            _validate_component(segment, maximum=255)
            for segment in value[1:].split('/')
        )
        return cls(segments)

    def __str__(self):
        return '/' + '/'.join(self.segments)

    def child(self, name):
        return SMBPath(self.segments + (_validate_component(name, maximum=255),))

    def parent(self):
        if not self.segments:
            return self
        return SMBPath(self.segments[:-1])

    @property
    def name(self):
        return self.segments[-1] if self.segments else ''

    def to_unc(self, target_ip, share):
        if not isinstance(share, SMBShareName):
            raise SMBPathRejected('Invalid SMB share')
        try:
            clean_ip = ipaddress.ip_address(target_ip).compressed
        except ValueError as exc:
            raise SMBPathRejected('SMB UNC target must be a validated IP') from exc
        components = (clean_ip, share.value, *self.segments)
        return '\\\\' + '\\'.join(components)
