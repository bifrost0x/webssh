"""Layered, per-user SSH host-key trust storage."""

import base64
import binascii
import hashlib
import hmac
import os
import re
from collections.abc import MutableMapping
from datetime import datetime, timezone
from pathlib import Path

import paramiko
from paramiko.hostkeys import HostKeyEntry

from .audit_logger import log_info, log_warning
from .storage_utils import (
    atomic_write_bytes,
    fsync_parent_directory,
    storage_lock,
)


class RevokedHostKeyError(paramiko.SSHException):
    """Raised when a server presents an explicitly revoked host key."""


class _ParsedHostKeyFile:
    def __init__(self, raw=b""):
        self.raw = raw
        self.trusted = paramiko.HostKeys()
        self.revoked = paramiko.HostKeys()


def _host_pattern_matches(hostname, pattern):
    if pattern.startswith("|1|"):
        candidates = (hostname, hostname.lower())
        try:
            return any(
                hmac.compare_digest(
                    paramiko.HostKeys.hash_host(candidate, pattern),
                    pattern,
                )
                for candidate in dict.fromkeys(candidates)
            )
        except (AssertionError, TypeError, ValueError, binascii.Error):
            return False

    expression = re.escape(pattern)
    expression = expression.replace(r"\*", ".*").replace(r"\?", ".")
    return re.fullmatch(expression, hostname, re.IGNORECASE) is not None


def _entry_matches_hostname(hostname, entry):
    matched_positive = False
    for host_pattern in entry.hostnames:
        negated = host_pattern.startswith("!")
        pattern = host_pattern[1:] if negated else host_pattern
        if not _host_pattern_matches(hostname, pattern):
            continue
        if negated:
            return False
        matched_positive = True
    return matched_positive


def _host_pattern_is_valid(host_pattern):
    pattern = (
        host_pattern[1:]
        if host_pattern.startswith("!")
        else host_pattern
    )
    if not pattern:
        return False
    if not pattern.startswith("|"):
        return True

    fields = pattern.split("|")
    if len(fields) != 4 or fields[:2] != ["", "1"]:
        return False
    try:
        salt = base64.b64decode(fields[2], validate=True)
        digest = base64.b64decode(fields[3], validate=True)
    except (ValueError, binascii.Error):
        return False
    return len(salt) == 20 and len(digest) == 20


def _host_identity_token(host_pattern):
    """Normalize a literal pattern identity without conflating salted hashes."""
    negated = host_pattern.startswith("!")
    pattern = host_pattern[1:] if negated else host_pattern
    if not pattern.startswith("|1|"):
        pattern = pattern.casefold()
    return f"!{pattern}" if negated else pattern


class _EffectiveKeyMapping(MutableMapping):
    """Paramiko-compatible key mapping returned for one runtime hostname."""

    def __init__(self, hostname, values, host_keys):
        self._hostname = hostname
        self._values = values
        self._host_keys = host_keys

    def __getitem__(self, key):
        return self._values[key]

    def __setitem__(self, key, value):
        self._host_keys.add(self._hostname, key, value)
        self._values[key] = value

    def __delitem__(self, key):
        raise TypeError("Layered host-key lookups do not support deletion")

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)

    def keys(self):
        # SSHClient.connect indexes keys()[0], unlike a normal Mapping consumer.
        return list(self._values)


class _LayeredHostKeys(paramiko.HostKeys):
    """Resolve user trust before global trust by effective hostname match."""

    def __init__(self, global_file, user_file):
        super().__init__()
        self._global_file = global_file
        self._user_file = user_file

    def lookup(self, hostname):
        effective = {}
        for host_keys in (
            self._user_file.trusted,
            self._global_file.trusted,
        ):
            for entry in host_keys._entries:
                if not _entry_matches_hostname(hostname, entry):
                    continue
                key_type = entry.key.get_name()
                if key_type in effective:
                    continue
                if self.is_revoked(hostname, entry.key):
                    continue
                effective[key_type] = entry.key
        if not effective:
            return None
        return _EffectiveKeyMapping(hostname, effective, self)

    def add(self, hostname, keytype, key):
        self._user_file.trusted.add(hostname, keytype, key)

    def check(self, hostname, key):
        keys = self.lookup(hostname)
        return (
            keys is not None
            and keys.get(key.get_name()) is not None
            and keys[key.get_name()].asbytes() == key.asbytes()
        )

    def keys(self):
        result = []
        for host_keys in (
            self._user_file.trusted,
            self._global_file.trusted,
        ):
            for hostname in host_keys.keys():
                if hostname not in result:
                    result.append(hostname)
        return result

    def is_revoked(self, hostname, key):
        for host_keys in (
            self._user_file.revoked,
            self._global_file.revoked,
        ):
            for entry in host_keys._entries:
                if (
                    entry.key == key
                    and _entry_matches_hostname(hostname, entry)
                ):
                    return True
        return False


class _PerUserMissingHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, store):
        self.store = store

    def missing_host_key(self, client, hostname, key):
        fingerprint = binascii.hexlify(key.get_fingerprint()).decode("ascii")
        formatted = ":".join(
            fingerprint[index:index + 2]
            for index in range(0, len(fingerprint), 2)
        )
        log_warning(
            "SECURITY: New SSH host key detected",
            host=hostname,
            key_type=key.get_name(),
            fingerprint=formatted,
            user_id=self.store.user_id,
        )
        self.store.record(hostname, key)
        client.get_host_keys().add(hostname, key.get_name(), key)
        log_info(
            "Host key stored",
            path=str(self.store.user_path),
            user_id=self.store.user_id,
        )


class HostKeyStore:
    """Read global trust and persist newly accepted keys per application user."""

    def __init__(self, user_id: int, global_path: Path, users_root: Path):
        if isinstance(user_id, bool) or not isinstance(user_id, (int, str)):
            raise TypeError("user_id must be a positive integer")
        if isinstance(user_id, str):
            normalized = user_id.strip()
            if not normalized.isascii() or not normalized.isdigit():
                raise ValueError("user_id must be a positive integer")
            canonical_user_id = int(normalized)
        else:
            canonical_user_id = user_id
        if canonical_user_id <= 0:
            raise ValueError("user_id must be a positive integer")

        self.user_id = canonical_user_id
        self.global_path = Path(global_path)
        self.users_root = Path(users_root)
        self.user_path = (
            self.users_root / f"user_{self.user_id}" / "known_hosts"
        )
        # One process-local lock per canonical database user. The registry is
        # bounded by the number of users observed by this single-worker app.
        self._lock_key = f"host_keys:{self.user_id}"

    def load_into(self, client: paramiko.SSHClient) -> None:
        """Install effective user-first trust on a Paramiko SSH client."""
        global_file = self._load_or_empty(self.global_path)
        user_file = self._load_or_empty(self.user_path)
        client._host_keys = _LayeredHostKeys(global_file, user_file)

    def missing_key_policy(self) -> paramiko.MissingHostKeyPolicy:
        return _PerUserMissingHostKeyPolicy(self)

    def record(self, hostname: str, key: paramiko.PKey) -> None:
        """Append a first-seen key without rewriting the user's raw file."""
        with storage_lock(self._lock_key):
            self._ensure_private_directory()
            global_file = self._load_or_empty(self.global_path)
            user_file = self._load_or_empty(self.user_path)
            layered = _LayeredHostKeys(global_file, user_file)

            if layered.is_revoked(hostname, key):
                raise RevokedHostKeyError(
                    f"Host key for {hostname!r} is revoked"
                )

            user_keys = _LayeredHostKeys(
                _ParsedHostKeyFile(), user_file
            ).lookup(hostname)
            existing = (
                user_keys.get(key.get_name())
                if user_keys is not None
                else None
            )
            if existing is not None:
                if existing != key:
                    raise paramiko.BadHostKeyException(
                        hostname, key, existing
                    )
                return

            prefix = user_file.raw
            if prefix and not prefix.endswith(b"\n"):
                prefix += b"\n"
            line = HostKeyEntry([hostname], key).to_line()
            atomic_write_bytes(
                self.user_path,
                prefix + line.encode("utf-8"),
                mode=0o600,
            )

    def list_entries(self):
        """Return management metadata for this user's trusted keys."""
        return self.list_file(
            self.user_path,
            scope="user",
            owner_id=self.user_id,
        )

    def delete_entry(self, entry_id):
        """Delete one trusted user key while preserving unrelated raw lines."""
        return self.delete_file_entry(
            self.user_path,
            entry_id,
            scope="user",
            owner_id=self.user_id,
            lock_key=self._lock_key,
        )

    @classmethod
    def list_file(cls, path, *, scope, owner_id):
        path = Path(path)
        try:
            raw = path.read_bytes()
            modified = datetime.fromtimestamp(
                path.stat().st_mtime,
                timezone.utc,
            ).isoformat()
        except FileNotFoundError:
            return []

        entries = []
        for raw_line in raw.splitlines():
            parsed = cls._management_entry(
                raw_line,
                scope=scope,
                owner_id=owner_id,
                timestamp=modified,
            )
            if parsed is not None:
                entries.append(parsed)
        return entries

    @classmethod
    def delete_file_entry(
        cls,
        path,
        entry_id,
        *,
        scope,
        owner_id,
        lock_key,
    ):
        if not isinstance(entry_id, str) or not re.fullmatch(
            r"[0-9a-f]{64}", entry_id
        ):
            return False
        path = Path(path)
        with storage_lock(lock_key):
            try:
                raw = path.read_bytes()
            except FileNotFoundError:
                return False
            kept = []
            removed = False
            for raw_line in raw.splitlines(keepends=True):
                candidate = cls._management_entry(
                    raw_line.rstrip(b"\r\n"),
                    scope=scope,
                    owner_id=owner_id,
                    timestamp=None,
                )
                if candidate is not None and candidate["id"] == entry_id:
                    removed = True
                    continue
                kept.append(raw_line)
            if not removed:
                return False
            atomic_write_bytes(path, b"".join(kept), mode=0o600)
            return True

    @classmethod
    def add_file_entry(cls, path, value, *, scope, owner_id, lock_key):
        """Append one validated known_hosts entry without exposing stored keys."""
        if not isinstance(value, str):
            return None, "Host key entry must be text"
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError:
            return None, "Invalid known_hosts entry"
        if not encoded or len(encoded) > 16384 or "\n" in value or "\r" in value:
            return None, "Enter exactly one known_hosts entry"

        fields = re.split(r"[ \t]+", value.strip())
        marker = None
        if fields and fields[0].startswith("@"):
            marker = fields.pop(0)
        if marker not in (None, "@revoked") or len(fields) < 3:
            return None, "Invalid or unsupported known_hosts entry"
        try:
            entry = HostKeyEntry.from_line(" ".join(fields[:3]))
        except Exception:
            return None, "Invalid known_hosts entry"
        if entry is None or not entry.hostnames or not all(
            _host_pattern_is_valid(pattern) for pattern in entry.hostnames
        ):
            return None, "Invalid known_hosts entry"

        canonical = " ".join(
            ([marker] if marker else []) + fields[:3]
        ).encode("utf-8")
        candidate = cls._management_entry(
            canonical,
            scope=scope,
            owner_id=owner_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        path = Path(path)
        with storage_lock(lock_key):
            try:
                raw = path.read_bytes()
                # Refuse to append to a malformed trust store.
                cls._load_strict(path)
            except FileNotFoundError:
                raw = b""

            for raw_line in raw.splitlines():
                existing_line = raw_line.decode("utf-8").strip()
                if not existing_line or existing_line.startswith("#"):
                    continue
                existing_fields = re.split(r"[ \t]+", existing_line)
                existing_marker = None
                if existing_fields[0].startswith("@"):
                    existing_marker = existing_fields.pop(0)
                existing_entry = HostKeyEntry.from_line(
                    " ".join(existing_fields[:3])
                )
                overlapping_hosts = not set(map(
                    _host_identity_token, existing_entry.hostnames
                )).isdisjoint(map(_host_identity_token, entry.hostnames))
                same_identity = (
                    overlapping_hosts
                    and existing_marker == marker
                    and existing_entry.key.get_name() == entry.key.get_name()
                )
                if not same_identity:
                    continue
                if existing_entry.key == entry.key:
                    return None, "Host key entry already exists"
                return None, (
                    "A different key already exists for this host and algorithm; "
                    "verify and remove it first"
                )

            prefix = raw
            if prefix and not prefix.endswith(b"\n"):
                prefix += b"\n"
            path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_bytes(path, prefix + canonical + b"\n", mode=0o600)
        return candidate, None

    @staticmethod
    def _management_entry(raw_line, *, scope, owner_id, timestamp):
        try:
            line = raw_line.decode("utf-8").strip()
        except UnicodeDecodeError as exc:
            raise paramiko.SSHException(
                "Invalid Unicode in known_hosts"
            ) from exc
        if not line or line.startswith("#"):
            return None
        fields = re.split(r"[ \t]+", line)
        marker = None
        if fields[0].startswith("@"):
            marker = fields.pop(0)
        if len(fields) < 3:
            raise paramiko.SSHException("Invalid known_hosts entry")
        try:
            entry = HostKeyEntry.from_line(" ".join(fields[:3]))
        except Exception as exc:
            raise paramiko.SSHException(
                "Invalid known_hosts entry"
            ) from exc
        if entry is None or not entry.hostnames:
            raise paramiko.SSHException("Invalid known_hosts entry")

        hosts = [
            {
                "host": parsed_host,
                "port": parsed_port,
            }
            for parsed_host, parsed_port in (
                HostKeyStore._split_management_host(host_token)
                for host_token in entry.hostnames
            )
        ]
        host = hosts[0]["host"]
        port = hosts[0]["port"]
        identity = b"\0".join((
            scope.encode("ascii"),
            str(owner_id if owner_id is not None else "").encode("ascii"),
            raw_line,
        ))
        fingerprint = base64.b64encode(
            hashlib.sha256(entry.key.asbytes()).digest()
        ).decode("ascii").rstrip("=")
        return {
            "id": hashlib.sha256(identity).hexdigest(),
            "host": host,
            "port": port,
            "hosts": hosts,
            "marker": marker,
            "algorithm": entry.key.get_name(),
            "fingerprint": f"SHA256:{fingerprint}",
            "scope": scope,
            "owner_id": owner_id,
            "first_seen": timestamp,
            "last_seen": timestamp,
        }

    @staticmethod
    def _split_management_host(host_token):
        if host_token.startswith("|1|"):
            return "(hashed hostname)", None
        match = re.fullmatch(r"\[(.+)]:(\d+)", host_token)
        if match:
            return match.group(1), int(match.group(2))
        return host_token, 22

    def _ensure_private_directory(self) -> None:
        self.users_root.mkdir(parents=True, exist_ok=True)
        user_directory = self.user_path.parent
        created = False
        try:
            user_directory.mkdir(mode=0o700)
            created = True
        except FileExistsError:
            if not user_directory.is_dir():
                raise
        os.chmod(user_directory, 0o700)
        if created or not self.user_path.exists():
            fsync_parent_directory(user_directory)

    @classmethod
    def _load_or_empty(cls, path):
        try:
            return cls._load_strict(path)
        except FileNotFoundError:
            return _ParsedHostKeyFile()

    @staticmethod
    def _load_strict(path: Path) -> _ParsedHostKeyFile:
        raw = Path(path).read_bytes()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise paramiko.SSHException(
                "Invalid Unicode in known_hosts"
            ) from exc

        parsed = _ParsedHostKeyFile(raw)
        for line_number, raw_line in enumerate(text.splitlines(), 1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            marker = None
            fields = re.split(r"[ \t]+", line)
            if fields[0].startswith("@"):
                marker = fields.pop(0)
                if marker not in ("@revoked", "@cert-authority"):
                    raise paramiko.SSHException(
                        f"Unsupported known_hosts marker on line {line_number}"
                    )
            if len(fields) < 3:
                raise paramiko.SSHException(
                    f"Invalid known_hosts entry on line {line_number}"
                )
            entry_line = " ".join(fields[:3])

            try:
                entry = HostKeyEntry.from_line(entry_line, line_number)
            except Exception as exc:
                raise paramiko.SSHException(
                    f"Invalid known_hosts entry on line {line_number}"
                ) from exc
            if entry is None:
                raise paramiko.SSHException(
                    f"Invalid known_hosts entry on line {line_number}"
                )
            if not entry.hostnames or not all(
                _host_pattern_is_valid(pattern)
                for pattern in entry.hostnames
            ):
                raise paramiko.SSHException(
                    f"Invalid known_hosts entry on line {line_number}"
                )

            if marker == "@cert-authority":
                log_warning(
                    "Unsupported @cert-authority known_hosts entry ignored",
                    line=line_number,
                )
            elif marker == "@revoked":
                parsed.revoked._entries.append(entry)
            else:
                parsed.trusted._entries.append(entry)
        return parsed
