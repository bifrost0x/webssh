import os
import stat
import threading
from pathlib import Path

import paramiko
import pytest

from app.host_key_store import HostKeyStore


def _key():
    return paramiko.RSAKey.generate(1024)


def _write_host_keys(path, *entries):
    path.parent.mkdir(parents=True, exist_ok=True)
    host_keys = paramiko.HostKeys()
    for hostname, key in entries:
        host_keys.add(hostname, key.get_name(), key)
    host_keys.save(str(path))


def _known_hosts_line(hostname, key, marker=None, comment=None):
    fields = [hostname, key.get_name(), key.get_base64()]
    if marker:
        fields.insert(0, marker)
    if comment:
        fields.append(comment)
    return " ".join(fields) + "\n"


class _FakeSecurityOptions:
    def __init__(self):
        self.key_types = ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]


class _FakeTransport:
    remote_key = None

    def __init__(self, _sock, disabled_algorithms=None):
        self.disabled_algorithms = disabled_algorithms

    def use_compression(self, compress=False):
        pass

    def get_security_options(self):
        return _FakeSecurityOptions()

    def start_client(self, timeout=None):
        pass

    def get_remote_server_key(self):
        return self.remote_key


class _SuccessfulAuthStrategy:
    def authenticate(self, transport):
        return transport


def test_user_path_is_canonical_and_private(tmp_path):
    store = HostKeyStore("007", tmp_path / "known_hosts", tmp_path / "users")

    store.record("host", _key())

    assert store.user_path == tmp_path / "users" / "user_7" / "known_hosts"
    if os.name == "posix":
        assert stat.S_IMODE(store.user_path.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(store.user_path.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "user_id",
    [None, "", 0, -1, True, 7.5, b"7", "not-an-id"],
)
def test_invalid_user_id_is_rejected(tmp_path, user_id):
    with pytest.raises((TypeError, ValueError)):
        HostKeyStore(user_id, tmp_path / "known_hosts", tmp_path / "users")


def test_new_key_is_written_only_to_own_user_store(tmp_path):
    global_path = tmp_path / "known_hosts"
    store = HostKeyStore(7, global_path, tmp_path / "users")

    store.record("[host]:2222", _key())

    assert "[host]:2222" in paramiko.HostKeys(str(store.user_path))
    assert not global_path.exists()


def test_different_users_have_isolated_trust(tmp_path):
    key_one = _key()
    key_two = _key()
    first = HostKeyStore(1, tmp_path / "known_hosts", tmp_path / "users")
    second = HostKeyStore(2, tmp_path / "known_hosts", tmp_path / "users")

    first.record("host", key_one)
    second.record("host", key_two)

    assert paramiko.HostKeys(str(first.user_path)).lookup("host")[
        key_one.get_name()
    ] == key_one
    assert paramiko.HostKeys(str(second.user_path)).lookup("host")[
        key_two.get_name()
    ] == key_two


def test_load_into_layers_global_then_user_with_user_precedence(tmp_path):
    global_key = _key()
    user_key = _key()
    global_path = tmp_path / "known_hosts"
    store = HostKeyStore(7, global_path, tmp_path / "users")
    _write_host_keys(global_path, ("shared", global_key), ("global-only", _key()))
    _write_host_keys(store.user_path, ("shared", user_key), ("user-only", _key()))

    client = paramiko.SSHClient()
    store.load_into(client)

    loaded = client.get_host_keys()
    assert loaded.lookup("shared")[user_key.get_name()] == user_key
    assert "global-only" in loaded
    assert "user-only" in loaded


@pytest.mark.parametrize(
    ("global_hashed", "user_hashed"),
    [(True, False), (False, True), (True, True)],
)
def test_user_layer_wins_by_effective_hostname_across_hash_forms(
        tmp_path, global_hashed, user_hashed):
    hostname = "[host.example]:2222"
    global_key = _key()
    user_key = _key()
    global_path = tmp_path / "known_hosts"
    store = HostKeyStore(7, global_path, tmp_path / "users")
    global_token = (
        paramiko.HostKeys.hash_host(hostname)
        if global_hashed else hostname
    )
    user_token = (
        paramiko.HostKeys.hash_host(hostname)
        if user_hashed else hostname
    )
    _write_host_keys(global_path, (global_token, global_key))
    _write_host_keys(store.user_path, (user_token, user_key))

    client = paramiko.SSHClient()
    store.load_into(client)

    effective = client.get_host_keys().lookup(hostname)
    assert effective[user_key.get_name()] == user_key
    assert effective[user_key.get_name()] != global_key


def test_distinct_hash_salts_still_apply_user_precedence(tmp_path):
    hostname = "host.example"
    global_token = paramiko.HostKeys.hash_host(hostname)
    user_token = paramiko.HostKeys.hash_host(hostname)
    assert global_token != user_token
    global_key = _key()
    user_key = _key()
    global_path = tmp_path / "known_hosts"
    store = HostKeyStore(7, global_path, tmp_path / "users")
    _write_host_keys(global_path, (global_token, global_key))
    _write_host_keys(store.user_path, (user_token, user_key))

    client = paramiko.SSHClient()
    store.load_into(client)

    assert client.get_host_keys().lookup(hostname)[
        user_key.get_name()
    ] == user_key


@pytest.mark.parametrize("pattern_store", ["global", "user"])
def test_normal_trust_uses_openssh_patterns_and_negation(
        tmp_path, pattern_store):
    key = _key()
    store = HostKeyStore(
        7, tmp_path / "known_hosts", tmp_path / "users"
    )
    pattern_path = (
        store.global_path
        if pattern_store == "global"
        else store.user_path
    )
    pattern_path.parent.mkdir(parents=True, exist_ok=True)
    pattern_path.write_text(
        _known_hosts_line(
            "*.EXAMPLE.com,!blocked.example.com", key
        ),
        encoding="utf-8",
    )

    client = paramiko.SSHClient()
    store.load_into(client)

    assert client.get_host_keys().check("api.example.COM", key)
    assert not client.get_host_keys().check("blocked.example.com", key)
    _FakeTransport.remote_key = key
    result = client.connect(
        "api.example.COM",
        username="alice",
        sock=object(),
        auth_strategy=_SuccessfulAuthStrategy(),
        transport_factory=_FakeTransport,
    )
    assert isinstance(result, _FakeTransport)


def test_openssh_patterns_escape_character_classes_and_match_host_ports(
        tmp_path):
    literal_key = _key()
    port_key = _key()
    store = HostKeyStore(
        7, tmp_path / "known_hosts", tmp_path / "users"
    )
    store.global_path.write_text(
        _known_hosts_line("host[12].example", literal_key)
        + _known_hosts_line("[*.example.com]:22??", port_key),
        encoding="utf-8",
    )

    client = paramiko.SSHClient()
    store.load_into(client)

    loaded = client.get_host_keys()
    assert loaded.check("host[12].example", literal_key)
    assert not loaded.check("host1.example", literal_key)
    assert loaded.check("[HOST.EXAMPLE.COM]:2222", port_key)


def test_hashed_negative_pattern_excludes_host_from_positive_wildcard(
        tmp_path):
    excluded = "blocked.example.com"
    key = _key()
    hashed = paramiko.HostKeys.hash_host(excluded)
    store = HostKeyStore(
        7, tmp_path / "known_hosts", tmp_path / "users"
    )
    store.global_path.write_text(
        _known_hosts_line(f"*,!{hashed}", key),
        encoding="utf-8",
    )

    client = paramiko.SSHClient()
    store.load_into(client)

    assert client.get_host_keys().check("allowed.example.com", key)
    assert not client.get_host_keys().check(excluded, key)


def test_real_ssh_client_connect_uses_effective_user_layer(tmp_path):
    hostname = "host.example"
    global_key = _key()
    user_key = _key()
    global_path = tmp_path / "known_hosts"
    store = HostKeyStore(7, global_path, tmp_path / "users")
    _write_host_keys(
        global_path,
        (paramiko.HostKeys.hash_host(hostname), global_key),
    )
    _write_host_keys(store.user_path, (hostname, user_key))
    client = paramiko.SSHClient()
    store.load_into(client)
    _FakeTransport.remote_key = user_key

    result = client.connect(
        hostname,
        username="alice",
        sock=object(),
        auth_strategy=_SuccessfulAuthStrategy(),
        transport_factory=_FakeTransport,
    )

    assert isinstance(result, _FakeTransport)


def test_real_ssh_client_connect_rejects_global_key_overridden_by_user(
        tmp_path):
    hostname = "host.example"
    global_key = _key()
    user_key = _key()
    global_path = tmp_path / "known_hosts"
    store = HostKeyStore(7, global_path, tmp_path / "users")
    _write_host_keys(global_path, (hostname, global_key))
    _write_host_keys(
        store.user_path,
        (paramiko.HostKeys.hash_host(hostname), user_key),
    )
    client = paramiko.SSHClient()
    store.load_into(client)
    _FakeTransport.remote_key = global_key

    with pytest.raises(paramiko.BadHostKeyException):
        client.connect(
            hostname,
            username="alice",
            sock=object(),
            auth_strategy=_SuccessfulAuthStrategy(),
            transport_factory=_FakeTransport,
        )


@pytest.mark.parametrize("marker_store", ["global", "user"])
def test_revoked_marker_blocks_key_even_when_normally_trusted(
        tmp_path, marker_store):
    hostname = "host.example"
    key = _key()
    global_path = tmp_path / "known_hosts"
    store = HostKeyStore(7, global_path, tmp_path / "users")
    marker_path = (
        global_path if marker_store == "global" else store.user_path
    )
    marker_path.parent.mkdir(parents=True, exist_ok=True)
    original = (
        _known_hosts_line(hostname, key, marker="@revoked")
        + _known_hosts_line(hostname, key)
    ).encode("utf-8")
    marker_path.write_bytes(original)
    client = paramiko.SSHClient()
    store.load_into(client)
    client.set_missing_host_key_policy(store.missing_key_policy())
    _FakeTransport.remote_key = key

    with pytest.raises(paramiko.SSHException, match="revoked"):
        client.connect(
            hostname,
            username="alice",
            sock=object(),
            auth_strategy=_SuccessfulAuthStrategy(),
            transport_factory=_FakeTransport,
        )

    assert marker_path.read_bytes() == original
    if marker_store == "global":
        assert not store.user_path.exists()


def test_revoked_marker_does_not_block_different_key(tmp_path):
    hostname = "host.example"
    revoked_key = _key()
    replacement_key = _key()
    store = HostKeyStore(
        7, tmp_path / "known_hosts", tmp_path / "users"
    )
    store.user_path.parent.mkdir(parents=True)
    store.user_path.write_text(
        _known_hosts_line(hostname, revoked_key, marker="@revoked"),
        encoding="utf-8",
    )

    store.record(hostname, replacement_key)

    stored = store.user_path.read_text(encoding="utf-8")
    assert stored.startswith("@revoked ")
    assert replacement_key.get_base64() in stored


@pytest.mark.parametrize("marker_store", ["global", "user"])
def test_wildcard_revocation_blocks_record_and_connect_with_negation(
        tmp_path, marker_store):
    key = _key()
    store = HostKeyStore(
        7, tmp_path / "known_hosts", tmp_path / "users"
    )
    marker_path = (
        store.global_path
        if marker_store == "global"
        else store.user_path
    )
    marker_path.parent.mkdir(parents=True, exist_ok=True)
    original = (
        _known_hosts_line(
            "*.example.com,!allowed.example.com",
            key,
            marker="@revoked",
        )
        + _known_hosts_line("blocked.example.com", key)
        + _known_hosts_line("allowed.example.com", key)
    ).encode("utf-8")
    marker_path.write_bytes(original)

    with pytest.raises(paramiko.SSHException, match="revoked"):
        store.record("blocked.example.com", key)
    store.record("allowed.example.com", key)

    client = paramiko.SSHClient()
    store.load_into(client)
    client.set_missing_host_key_policy(store.missing_key_policy())
    _FakeTransport.remote_key = key
    with pytest.raises(paramiko.SSHException, match="revoked"):
        client.connect(
            "blocked.example.com",
            username="alice",
            sock=object(),
            auth_strategy=_SuccessfulAuthStrategy(),
            transport_factory=_FakeTransport,
        )
    result = client.connect(
        "allowed.example.com",
        username="alice",
        sock=object(),
        auth_strategy=_SuccessfulAuthStrategy(),
        transport_factory=_FakeTransport,
    )

    assert isinstance(result, _FakeTransport)
    assert marker_path.read_bytes() == original


@pytest.mark.parametrize("marker_store", ["global", "user"])
def test_cert_authority_is_ignored_without_hiding_following_trust(
        tmp_path, monkeypatch, marker_store):
    hostname = "host.example"
    ca_key = _key()
    host_key = _key()
    store = HostKeyStore(
        7, tmp_path / "known_hosts", tmp_path / "users"
    )
    marker_path = (
        store.global_path
        if marker_store == "global"
        else store.user_path
    )
    marker_path.parent.mkdir(parents=True, exist_ok=True)
    marker_path.write_text(
        _known_hosts_line(hostname, ca_key, marker="@cert-authority")
        + _known_hosts_line(hostname, host_key),
        encoding="utf-8",
    )
    warnings = []
    monkeypatch.setattr(
        "app.host_key_store.log_warning",
        lambda message, **fields: warnings.append((message, fields)),
    )

    client = paramiko.SSHClient()
    store.load_into(client)

    assert client.get_host_keys().lookup(hostname)[
        host_key.get_name()
    ] == host_key
    assert client.get_host_keys().check(hostname, ca_key) is False
    assert warnings == [(
        "Unsupported @cert-authority known_hosts entry ignored",
        {"line": 1},
    )]


@pytest.mark.parametrize("marker", ["@revoked", "@cert-authority"])
def test_malformed_marker_entry_fails_closed(tmp_path, marker):
    store = HostKeyStore(
        7, tmp_path / "known_hosts", tmp_path / "users"
    )
    store.user_path.parent.mkdir(parents=True)
    store.user_path.write_text(
        f"{marker} not-enough-fields\n",
        encoding="utf-8",
    )

    with pytest.raises(paramiko.SSHException):
        store.load_into(paramiko.SSHClient())


@pytest.mark.parametrize("marker", [None, "@revoked"])
def test_malformed_hashed_host_pattern_fails_closed(tmp_path, marker):
    store = HostKeyStore(
        7, tmp_path / "known_hosts", tmp_path / "users"
    )
    store.user_path.parent.mkdir(parents=True)
    key = _key()
    store.user_path.write_text(
        _known_hosts_line(
            "|1|invalid-salt|invalid-digest",
            key,
            marker=marker,
        ),
        encoding="utf-8",
    )

    with pytest.raises(paramiko.SSHException):
        store.load_into(paramiko.SSHClient())


@pytest.mark.parametrize("entry_store", ["global", "user"])
@pytest.mark.parametrize("marker", [None, "@revoked"])
def test_parser_accepts_arbitrary_field_whitespace_and_preserves_raw_bytes(
        tmp_path, entry_store, marker):
    hostname = "host.example"
    key = _key()
    store = HostKeyStore(
        7, tmp_path / "known_hosts", tmp_path / "users"
    )
    entry_path = (
        store.global_path
        if entry_store == "global"
        else store.user_path
    )
    entry_path.parent.mkdir(parents=True, exist_ok=True)
    marker_prefix = f"{marker}\t  " if marker else ""
    original = (
        f"{marker_prefix}{hostname}\t  {key.get_name()}    "
        f"{key.get_base64()}\t trailing comment\r\n"
    ).encode("utf-8")
    entry_path.write_bytes(original)

    client = paramiko.SSHClient()
    store.load_into(client)

    if marker:
        assert not client.get_host_keys().check(hostname, key)
        with pytest.raises(paramiko.SSHException, match="revoked"):
            store.record(hostname, key)
    else:
        assert client.get_host_keys().check(hostname, key)
        store.record(hostname, key)
    assert entry_path.read_bytes() == original


@pytest.mark.parametrize("which", ["global", "user"])
def test_load_into_fails_closed_for_malformed_store(tmp_path, which):
    global_path = tmp_path / "known_hosts"
    store = HostKeyStore(7, global_path, tmp_path / "users")
    malformed = global_path if which == "global" else store.user_path
    malformed.parent.mkdir(parents=True, exist_ok=True)
    malformed.write_text("not a host key\n", encoding="utf-8")

    with pytest.raises(paramiko.SSHException):
        store.load_into(paramiko.SSHClient())


def test_load_into_propagates_unreadable_store(tmp_path, monkeypatch):
    global_path = tmp_path / "known_hosts"
    store = HostKeyStore(7, global_path, tmp_path / "users")
    _write_host_keys(global_path, ("host", _key()))
    original = Path.open

    def fail_global(path, *args, **kwargs):
        if path == global_path:
            raise OSError("read denied")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail_global)

    with pytest.raises(OSError, match="read denied"):
        store.load_into(paramiko.SSHClient())


def test_parallel_first_seen_keys_are_both_preserved(tmp_path):
    store = HostKeyStore(7, tmp_path / "known_hosts", tmp_path / "users")
    first_key = _key()
    second_key = _key()
    barrier = threading.Barrier(3)
    errors = []

    def record(hostname, key):
        barrier.wait()
        try:
            store.record(hostname, key)
        except Exception as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    threads = [
        threading.Thread(target=record, args=("first", first_key)),
        threading.Thread(target=record, args=("second", second_key)),
    ]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout=5)

    assert errors == []
    assert not any(thread.is_alive() for thread in threads)
    stored = paramiko.HostKeys(str(store.user_path))
    assert stored.lookup("first")[first_key.get_name()] == first_key
    assert stored.lookup("second")[second_key.get_name()] == second_key


def test_same_host_same_key_type_race_never_auto_accepts_change(tmp_path):
    store = HostKeyStore(7, tmp_path / "known_hosts", tmp_path / "users")
    keys = [_key(), _key()]
    barrier = threading.Barrier(3)
    errors = []

    def record(key):
        barrier.wait()
        try:
            store.record("same-host", key)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=record, args=(key,)) for key in keys]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout=5)

    assert len(errors) == 1
    assert isinstance(errors[0], paramiko.BadHostKeyException)
    stored = paramiko.HostKeys(str(store.user_path))
    assert len(stored.lookup("same-host")) == 1


def test_repeated_identical_key_is_idempotent(tmp_path):
    store = HostKeyStore(7, tmp_path / "known_hosts", tmp_path / "users")
    key = _key()

    store.record("host", key)
    before = store.user_path.read_bytes()
    store.record("host", key)

    assert store.user_path.read_bytes() == before


def test_write_failure_preserves_previous_file(tmp_path, monkeypatch):
    store = HostKeyStore(7, tmp_path / "known_hosts", tmp_path / "users")
    store.record("existing", _key())
    before = store.user_path.read_bytes()

    def fail_write(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("app.host_key_store.atomic_write_bytes", fail_write)

    with pytest.raises(OSError, match="disk full"):
        store.record("new", _key())

    assert store.user_path.read_bytes() == before
    assert "new" not in paramiko.HostKeys(str(store.user_path))


def test_record_preserves_comments_and_multi_host_lines_byte_for_byte(
        tmp_path):
    store = HostKeyStore(7, tmp_path / "known_hosts", tmp_path / "users")
    existing_key = _key()
    new_key = _key()
    store.user_path.parent.mkdir(parents=True)
    prefix = (
        b"# operator comment\r\n"
        + _known_hosts_line(
            "host.example,alias.example",
            existing_key,
            comment="keep-this-comment",
        ).replace("\n", "\r\n").encode("utf-8")
    )
    store.user_path.write_bytes(prefix)

    store.record("new.example", new_key)

    updated = store.user_path.read_bytes()
    assert updated.startswith(prefix)
    assert updated[len(prefix):] == _known_hosts_line(
        "new.example", new_key
    ).encode("utf-8")


def test_record_does_not_rewrite_or_duplicate_effective_multi_host_key(
        tmp_path):
    store = HostKeyStore(7, tmp_path / "known_hosts", tmp_path / "users")
    key = _key()
    store.user_path.parent.mkdir(parents=True)
    original = (
        b"# unchanged\n"
        + _known_hosts_line(
            "host.example,alias.example", key, comment="unchanged"
        ).encode("utf-8")
    )
    store.user_path.write_bytes(original)

    store.record("alias.example", key)

    assert store.user_path.read_bytes() == original


def test_record_rejects_effective_multi_host_key_change_without_rewrite(
        tmp_path):
    store = HostKeyStore(7, tmp_path / "known_hosts", tmp_path / "users")
    original_key = _key()
    changed_key = _key()
    store.user_path.parent.mkdir(parents=True)
    original = _known_hosts_line(
        "host.example,alias.example", original_key
    ).encode("utf-8")
    store.user_path.write_bytes(original)

    with pytest.raises(paramiko.BadHostKeyException):
        store.record("alias.example", changed_key)

    assert store.user_path.read_bytes() == original


def test_missing_policy_records_nondefault_port_and_updates_client(tmp_path):
    store = HostKeyStore(7, tmp_path / "known_hosts", tmp_path / "users")
    client = paramiko.SSHClient()
    key = _key()

    store.missing_key_policy().missing_host_key(
        client, "[host.example]:2222", key
    )

    stored = paramiko.HostKeys(str(store.user_path))
    assert stored.lookup("[host.example]:2222")[key.get_name()] == key
    assert client.get_host_keys().lookup("[host.example]:2222")[
        key.get_name()
    ] == key


def test_record_reloads_disk_inside_lock(tmp_path):
    store = HostKeyStore(7, tmp_path / "known_hosts", tmp_path / "users")
    first = _key()
    second = _key()
    store.record("first", first)

    external = paramiko.HostKeys(str(store.user_path))
    external.add("external", second.get_name(), second)
    external.save(str(store.user_path))

    store.record("third", _key())

    stored = paramiko.HostKeys(str(store.user_path))
    assert "first" in stored
    assert "external" in stored
    assert "third" in stored


def test_first_user_directory_is_fsynced_before_host_key_write(
        tmp_path, monkeypatch):
    store = HostKeyStore(7, tmp_path / "known_hosts", tmp_path / "users")
    events = []
    monkeypatch.setattr(
        "app.host_key_store.fsync_parent_directory",
        lambda path: events.append(("fsync", path)),
    )
    monkeypatch.setattr(
        "app.host_key_store.atomic_write_bytes",
        lambda path, payload, mode: events.append(("write", path)),
    )

    store.record("host.example", _key())

    assert events == [
        ("fsync", store.user_path.parent),
        ("write", store.user_path),
    ]


def test_user_directory_fsync_failure_prevents_host_key_write(
        tmp_path, monkeypatch):
    store = HostKeyStore(7, tmp_path / "known_hosts", tmp_path / "users")
    writes = []

    def fail_fsync(_path):
        raise OSError("directory fsync failed")

    monkeypatch.setattr(
        "app.host_key_store.fsync_parent_directory", fail_fsync
    )
    monkeypatch.setattr(
        "app.host_key_store.atomic_write_bytes",
        lambda *args, **kwargs: writes.append((args, kwargs)),
    )

    with pytest.raises(OSError, match="directory fsync failed"):
        store.record("host.example", _key())

    assert writes == []
    assert not store.user_path.exists()


def test_retry_repeats_parent_fsync_after_first_fsync_failure(
        tmp_path, monkeypatch):
    store = HostKeyStore(7, tmp_path / "known_hosts", tmp_path / "users")
    events = []

    def flaky_fsync(path):
        events.append(("fsync", path))
        if len(events) == 1:
            raise OSError("first fsync failed")

    monkeypatch.setattr(
        "app.host_key_store.fsync_parent_directory", flaky_fsync
    )
    monkeypatch.setattr(
        "app.host_key_store.atomic_write_bytes",
        lambda path, payload, mode: events.append(("write", path)),
    )

    with pytest.raises(OSError, match="first fsync failed"):
        store.record("host.example", _key())
    store.record("host.example", _key())

    assert events == [
        ("fsync", store.user_path.parent),
        ("fsync", store.user_path.parent),
        ("write", store.user_path),
    ]
