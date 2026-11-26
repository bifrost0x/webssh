"""Seeded entropy and a controllable clock for reproducible fixture runs.

The generator calls the unmodified application code. To make its output
repeatable, the entropy and time sources that code reads are replaced for the
duration of a run:

* ``os.urandom`` and the ``random`` module's ``_urandom`` (behind ``secrets``,
  ``uuid.uuid4``, Fernet IVs, AES-GCM nonces, scrypt salts and the OpenSSH key
  serializer) read a SHA-256 counter stream derived from a fixed seed.
* ``time.time``/``time.time_ns`` and ``datetime.datetime`` (as bound in the
  application modules and in the ``datetime`` module itself) read one clock
  that only moves when the generator advances it.
* ``bcrypt.gensalt`` returns a salt drawn from the same stream. The salt
  itself is produced inside bcrypt's native code and cannot be seeded
  otherwise; hashing still runs through the real ``bcrypt.hashpw``.

Randomness that stays inside OpenSSL (RSA key generation, randomized ECDSA,
PEM/PKCS#8 passphrase encryption) cannot be redirected. The generator avoids
it where possible and the manifest marks every artifact that keeps it.
"""

import base64
import contextlib
import datetime as _datetime_module
import hashlib
import os
import random
import sys
import time

_REAL_DATETIME = _datetime_module.datetime
_UTC = _datetime_module.timezone.utc
_BCRYPT_ALPHABET = (
    './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
)
_STANDARD_ALPHABET = (
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
)


class SeededStream:
    """Deterministic byte stream: SHA-256(seed || label || counter)."""

    def __init__(self, seed, label='entropy'):
        self._prefix = hashlib.sha256(
            f'{seed}\x00{label}'.encode('utf-8')
        ).digest()
        self._counter = 0
        self._buffer = b''

    def read(self, size):
        size = int(size)
        if size < 0:
            raise ValueError('negative size')
        while len(self._buffer) < size:
            block = hashlib.sha256(
                self._prefix + self._counter.to_bytes(8, 'big')
            ).digest()
            self._counter += 1
            self._buffer += block
        chunk, self._buffer = self._buffer[:size], self._buffer[size:]
        return chunk


class Clock:
    """Single source of 'now' for the whole run, in UTC."""

    def __init__(self, start):
        if start.tzinfo is None:
            raise ValueError('clock start must be timezone-aware')
        self.now = start.astimezone(_UTC)

    def advance(self, **delta):
        self.now += _datetime_module.timedelta(**delta)
        return self.now

    def set(self, value):
        self.now = value.astimezone(_UTC)
        return self.now

    def timestamp(self):
        return self.now.timestamp()


_active_clock = None


class _FrozenMeta(type):
    def __instancecheck__(cls, instance):
        return isinstance(instance, _REAL_DATETIME)

    def __subclasscheck__(cls, subclass):
        return issubclass(subclass, _REAL_DATETIME)


class FrozenDatetime(_REAL_DATETIME, metaclass=_FrozenMeta):
    """datetime whose now()/utcnow() read the active generator clock."""

    @classmethod
    def now(cls, tz=None):
        if _active_clock is None:
            return _REAL_DATETIME.now(tz)
        current = _active_clock.now
        if tz is None:
            # The generator runs with TZ=UTC, so local time equals UTC.
            return current.replace(tzinfo=None)
        return current.astimezone(tz)

    @classmethod
    def utcnow(cls):
        return cls.now(_UTC).replace(tzinfo=None)


def bcrypt_salt(stream, rounds):
    """Format 16 stream bytes as a bcrypt ``$2b$`` salt string."""
    encoded = base64.b64encode(stream.read(16)).decode('ascii').rstrip('=')
    translated = encoded.translate(
        str.maketrans(_STANDARD_ALPHABET, _BCRYPT_ALPHABET)
    )
    return f'$2b${rounds:02d}${translated}'.encode('ascii')


def _patch_datetime_bindings(patches):
    for name, module in list(sys.modules.items()):
        if module is None:
            continue
        if not (name == 'app' or name.startswith('app.') or name == 'config'):
            continue
        if getattr(module, 'datetime', None) is _REAL_DATETIME:
            patches.append((module, 'datetime', _REAL_DATETIME))
            module.datetime = FrozenDatetime


@contextlib.contextmanager
def deterministic(seed, clock, *, bcrypt_rounds):
    """Redirect entropy, wall-clock time and bcrypt salts for one run."""
    global _active_clock
    import bcrypt

    stream = SeededStream(seed)
    patches = [
        (os, 'urandom', os.urandom),
        (random, '_urandom', random._urandom),
        (time, 'time', time.time),
        (time, 'time_ns', time.time_ns),
        (bcrypt, 'gensalt', bcrypt.gensalt),
        (_datetime_module, 'datetime', _REAL_DATETIME),
    ]
    os.urandom = stream.read
    random._urandom = stream.read
    time.time = clock.timestamp
    time.time_ns = lambda: int(round(clock.timestamp() * 1_000_000)) * 1000
    bcrypt.gensalt = (
        lambda rounds=bcrypt_rounds, prefix=b'2b':
        bcrypt_salt(stream, bcrypt_rounds)
    )
    _datetime_module.datetime = FrozenDatetime
    _patch_datetime_bindings(patches)
    _active_clock = clock
    try:
        yield stream
    finally:
        _active_clock = None
        for target, name, original in reversed(patches):
            setattr(target, name, original)



@contextlib.contextmanager
def frozen_clock(clock):
    """Only the clock part of ``deterministic``, for verifying the fixture."""
    global _active_clock
    patches = [
        (time, 'time', time.time),
        (_datetime_module, 'datetime', _REAL_DATETIME),
    ]
    time.time = clock.timestamp
    _datetime_module.datetime = FrozenDatetime
    _patch_datetime_bindings(patches)
    _active_clock = clock
    try:
        yield clock
    finally:
        _active_clock = None
        for target, name, original in reversed(patches):
            setattr(target, name, original)
