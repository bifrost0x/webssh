from pathlib import Path
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


class _Entry:
    def __init__(self, dn, subject):
        self.dn = dn
        self.subject = subject


class _RecordingBackend:
    def __init__(self, entries=(), *, reject_password=False):
        self.entries = list(entries)
        self.reject_password = reject_password
        self.search_calls = []
        self.bind_calls = []

    def search_user(self, settings, bind_password, filter_expression):
        self.search_calls.append((settings, bind_password, filter_expression))
        return self.entries

    def verify_password(self, settings, distinguished_name, password):
        self.bind_calls.append((settings, distinguished_name, password))
        return not self.reject_password


class _FailoverBackend:
    def __init__(self, entries, *, unavailable=(), reject_password=False):
        self.entries = list(entries)
        self.unavailable = set(unavailable)
        self.reject_password = reject_password
        self.search_urls = []
        self.bind_urls = []
        self.probe_urls = []

    def _check_available(self, settings):
        from app.ldap_service import LDAPUnavailable

        if settings.url in self.unavailable:
            raise LDAPUnavailable('test endpoint unavailable')

    def search_user(self, settings, _bind_password, _filter_expression):
        self.search_urls.append(settings.url)
        self._check_available(settings)
        return self.entries

    def verify_password(self, settings, _distinguished_name, _password):
        self.bind_urls.append(settings.url)
        self._check_available(settings)
        return not self.reject_password

    def probe(self, settings, _bind_password):
        self.probe_urls.append(settings.url)
        self._check_available(settings)
        return True


def _settings(tmp_path):
    from app.ldap_service import LDAPSettings

    bind_secret = tmp_path / "ldap_bind_password"
    bind_secret.write_text("service-secret\n", encoding="utf-8")
    bind_secret.chmod(0o600)
    ca_file = tmp_path / "ldap_ca.pem"
    ca_file.write_text("test-ca", encoding="utf-8")
    return LDAPSettings(
        provider="primary",
        url="ldap://directory.example.com:389",
        base_dn="ou=people,dc=example,dc=com",
        bind_dn="cn=webssh,ou=services,dc=example,dc=com",
        bind_password_file=bind_secret,
        ca_file=ca_file,
        user_filter="(&(objectClass=person)(uid={username}))",
        unique_id_attribute="entryUUID",
        connect_timeout=4,
        operation_timeout=6,
    )


def _write_valid_ca(path):
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LDAP Test CA")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


def test_directory_lookup_escapes_filter_input_and_returns_one_identity(tmp_path):
    from app.ldap_service import LDAPDirectory, LDAPIdentity

    expected = LDAPIdentity(
        provider="primary",
        subject="86b4cc5f-3890-4f68-a32f-2b0e2b7381f1",
        distinguished_name="uid=alice,ou=people,dc=example,dc=com",
    )
    backend = _RecordingBackend(entries=[expected])
    directory = LDAPDirectory(_settings(tmp_path), backend=backend)

    result = directory.lookup("alice*)(uid=*)")

    assert result == expected
    assert backend.search_calls[0][1] == "service-secret"
    assert backend.search_calls[0][2] == (
        "(&(objectClass=person)(uid=alice\\2a\\29\\28uid=\\2a\\29))"
    )


@pytest.mark.parametrize("entry_count", (0, 2))
def test_directory_lookup_rejects_missing_or_ambiguous_matches(
    tmp_path,
    entry_count,
):
    from app.ldap_service import LDAPDirectory, LDAPLookupRejected

    entries = [
        _Entry(f"uid=user{index},dc=example,dc=com", f"id-{index}")
        for index in range(entry_count)
    ]
    directory = LDAPDirectory(
        _settings(tmp_path),
        backend=_RecordingBackend(entries=entries),
    )

    with pytest.raises(LDAPLookupRejected):
        directory.lookup("alice")


@pytest.mark.parametrize(
    "distinguished_name",
    ("uid=alice\x00,dc=example,dc=com", "x" * 2049),
)
def test_directory_lookup_rejects_unsafe_distinguished_name(
    tmp_path,
    distinguished_name,
):
    from app.ldap_service import LDAPDirectory, LDAPIdentity, LDAPLookupRejected

    identity = LDAPIdentity(
        provider="primary",
        subject="stable-id",
        distinguished_name=distinguished_name,
    )
    directory = LDAPDirectory(
        _settings(tmp_path),
        backend=_RecordingBackend(entries=[identity]),
    )

    with pytest.raises(LDAPLookupRejected):
        directory.lookup("alice")


def test_directory_authentication_never_accepts_an_empty_password(tmp_path):
    from app.ldap_service import LDAPDirectory

    backend = _RecordingBackend()
    directory = LDAPDirectory(_settings(tmp_path), backend=backend)

    assert directory.verify_password("uid=alice,dc=example,dc=com", "") is False
    assert backend.bind_calls == []


def test_directory_authentication_maps_bind_rejection_to_false(tmp_path):
    from app.ldap_service import LDAPDirectory

    backend = _RecordingBackend(reject_password=True)
    directory = LDAPDirectory(_settings(tmp_path), backend=backend)

    assert directory.verify_password(
        "uid=alice,dc=example,dc=com",
        "user-secret",
    ) is False
    assert backend.bind_calls[0][2] == "user-secret"


def test_directory_fails_over_and_keeps_the_working_endpoint_for_user_bind(
    tmp_path,
):
    from dataclasses import replace

    from app.ldap_service import LDAPDirectory, LDAPIdentity

    primary = 'ldaps://dc01.ad.example.com:636'
    backup = 'ldaps://dc02.ad.example.com:636'
    settings = replace(_settings(tmp_path), url=primary, backup_url=backup)
    identity = LDAPIdentity(
        provider='primary',
        subject='stable-id',
        distinguished_name='uid=alice,dc=example,dc=com',
    )
    backend = _FailoverBackend([identity], unavailable={primary})
    directory = LDAPDirectory(settings, backend=backend)

    assert directory.lookup('alice') == identity
    backend.unavailable.clear()
    assert directory.verify_password(identity.distinguished_name, 'user-secret')

    assert backend.search_urls == [primary, backup]
    assert backend.bind_urls == [backup]
    assert directory.active_url == backup


def test_directory_does_not_retry_an_authoritative_password_rejection(tmp_path):
    from dataclasses import replace

    from app.ldap_service import LDAPDirectory

    primary = 'ldaps://dc01.ad.example.com:636'
    backup = 'ldaps://dc02.ad.example.com:636'
    settings = replace(_settings(tmp_path), url=primary, backup_url=backup)
    backend = _FailoverBackend([], reject_password=True)
    directory = LDAPDirectory(settings, backend=backend)

    assert directory.verify_password('uid=alice,dc=example,dc=com', 'wrong') is False
    assert backend.bind_urls == [primary]


def test_directory_readiness_uses_the_backup_after_transport_failure(tmp_path):
    from dataclasses import replace

    from app.ldap_service import LDAPDirectory

    primary = 'ldap://dc01.ad.example.com:389'
    backup = 'ldap://dc02.ad.example.com:389'
    settings = replace(_settings(tmp_path), url=primary, backup_url=backup)
    backend = _FailoverBackend([], unavailable={primary})
    directory = LDAPDirectory(settings, backend=backend)

    assert directory.probe() is True
    assert backend.probe_urls == [primary, backup]
    assert directory.active_url == backup


def test_bind_secret_is_bounded_and_never_taken_from_environment(
    tmp_path,
    monkeypatch,
):
    from app.ldap_service import LDAPDirectory, LDAPUnavailable

    settings = _settings(tmp_path)
    Path(settings.bind_password_file).write_bytes(b"x" * (16 * 1024 + 1))
    monkeypatch.setenv("LDAP_BIND_PASSWORD", "environment-secret")
    backend = _RecordingBackend(entries=[_Entry("uid=alice", "id")])

    with pytest.raises(LDAPUnavailable):
        LDAPDirectory(settings, backend=backend).lookup("alice")

    assert backend.search_calls == []


class _FakeLDAPError(Exception):
    pass


class _FakeAuthenticationError(_FakeLDAPError):
    pass


class _FakeConnection:
    def __init__(self, entries):
        self.entries = entries
        self.search_call = None
        self.closed = False

    def search(self, *args, **kwargs):
        self.search_call = (args, kwargs)
        return self.entries

    def close(self, abandon_requests=False):
        self.closed = abandon_requests


class _FakeEntry(dict):
    def __init__(self, dn, attribute, value):
        super().__init__({attribute: [value]})
        self.dn = dn


class _FakeClient:
    def __init__(self, module, url, tls):
        self.module = module
        self.url = url
        self.tls = tls
        self.ca_cert = None
        self.cert_policy = None
        self.ignore_referrals = None
        self.server_chase_referrals = None
        self.credentials = None
        self.connect_timeout = None

    def set_ca_cert(self, value):
        self.ca_cert = value

    def set_cert_policy(self, value):
        self.cert_policy = value

    def set_ignore_referrals(self, value):
        self.ignore_referrals = value

    def set_server_chase_referrals(self, value):
        self.server_chase_referrals = value

    def set_credentials(self, mechanism, **kwargs):
        self.credentials = (mechanism, kwargs)

    def connect(self, timeout=None):
        self.connect_timeout = timeout
        if self.module.reject_bind:
            raise self.module.AuthenticationError("invalid credentials")
        return self.module.connection


class _FakeBonsai:
    LDAPError = _FakeLDAPError
    AuthenticationError = _FakeAuthenticationError

    class LDAPSearchScope:
        SUBTREE = 2

    def __init__(self, entries=(), *, reject_bind=False):
        self.connection = _FakeConnection(list(entries))
        self.clients = []
        self.reject_bind = reject_bind

    def LDAPClient(self, url, tls=False):
        client = _FakeClient(self, url, tls)
        self.clients.append(client)
        return client


@pytest.mark.parametrize(
    ("url", "expected_starttls"),
    (
        ("ldap://directory.example.com:389", True),
        ("ldaps://directory.example.com:636", False),
    ),
)
def test_bonsai_boundary_enforces_tls_verification_referral_and_size_limits(
    tmp_path,
    url,
    expected_starttls,
):
    from app.ldap_service import BonsaiBackend

    settings = _settings(tmp_path)
    settings = settings.__class__(**{**settings.__dict__, "url": url})
    entry = _FakeEntry(
        "uid=alice,ou=people,dc=example,dc=com",
        "entryUUID",
        "86b4cc5f-3890-4f68-a32f-2b0e2b7381f1",
    )
    bonsai = _FakeBonsai([entry])

    identities = BonsaiBackend(bonsai).search_user(
        settings,
        "service-secret",
        "(uid=alice)",
    )

    client = bonsai.clients[0]
    assert client.tls is expected_starttls
    assert client.ca_cert == str(settings.ca_file)
    assert client.cert_policy == "demand"
    assert client.ignore_referrals is True
    assert client.server_chase_referrals is False
    assert client.credentials == (
        "SIMPLE",
        {"user": settings.bind_dn, "password": "service-secret"},
    )
    assert client.connect_timeout == 4
    args, kwargs = bonsai.connection.search_call
    assert args == (
        settings.base_dn,
        2,
        "(uid=alice)",
        ["entryUUID"],
    )
    assert kwargs == {"timeout": 6, "sizelimit": 2}
    assert bonsai.connection.closed is True
    assert identities[0].subject == "86b4cc5f-3890-4f68-a32f-2b0e2b7381f1"


def test_bonsai_boundary_classifies_invalid_user_password(tmp_path):
    from app.ldap_service import BonsaiBackend

    backend = BonsaiBackend(_FakeBonsai(reject_bind=True))

    assert backend.verify_password(
        _settings(tmp_path),
        "uid=alice,dc=example,dc=com",
        "wrong-password",
    ) is False


def test_runtime_file_validation_accepts_private_secret_and_real_ca(tmp_path):
    from app.ldap_service import validate_runtime_files

    settings = _settings(tmp_path)
    _write_valid_ca(settings.ca_file)

    validate_runtime_files(settings)


def test_runtime_file_validation_fails_before_network_on_invalid_ca(tmp_path):
    from app.ldap_service import LDAPUnavailable, validate_runtime_files

    settings = _settings(tmp_path)

    with pytest.raises(LDAPUnavailable):
        validate_runtime_files(settings)
