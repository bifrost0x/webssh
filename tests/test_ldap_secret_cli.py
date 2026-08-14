import os
from pathlib import Path

from click.testing import CliRunner


TEST_CA = """-----BEGIN CERTIFICATE-----
MIIBszCCAVmgAwIBAgIUWmVuZXJhdGVkLWZvci11bml0LXRlc3QwCgYIKoZIzj0E
AwIwEzERMA8GA1UEAwwIVGVzdCBDQTAeFw0yNjAxMDEwMDAwMDBaFw0zNjAxMDEw
MDAwMDBaMBMxETAPBgNVBAMMCFRlc3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAATxlkM4GQ2sPHu6YlVvEVuEHV2emDNlt3y4tXaXv+Gf8fP+pWXxKSQPNeD1
LZ72hk5pvOBuq8zbM0t1F4YkuBXpo1MwUTAdBgNVHQ4EFgQU1dPzjHKFSCW10knm
qovkV9m60i4wHwYDVR0jBBgwFoAU1dPzjHKFSCW10knmqovkV9m60i4wDwYDVR0T
AQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEArBOKM0/8h3FBC81jDFuSq1cI
F7Gx1mOqQJ7yC+NdQzMCIF3v5QgYJ5gPiU8Qm7vJ7F3WJ7y+bM1D80k5M3wQvY0r
-----END CERTIFICATE-----
"""


def test_password_helper_writes_atomic_private_file(tmp_path):
    from ldap_secret_cli import cli

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["--secret-dir", str(tmp_path), "set-password", "--stdin"],
        input="service-secret\n",
    )

    target = tmp_path / "ldap_bind_password"
    assert result.exit_code == 0, result.output
    assert target.read_text(encoding="utf-8") == "service-secret"
    if os.name != "nt":
        assert target.stat().st_mode & 0o777 == 0o600
    assert not list(tmp_path.glob("*.tmp"))


def test_password_helper_rejects_empty_or_oversized_input(tmp_path):
    from ldap_secret_cli import cli

    runner = CliRunner()
    empty = runner.invoke(
        cli,
        ["--secret-dir", str(tmp_path), "set-password", "--stdin"],
        input="\n",
    )
    oversized = runner.invoke(
        cli,
        ["--secret-dir", str(tmp_path), "set-password", "--stdin"],
        input=("x" * (16 * 1024 + 1)) + "\n",
    )

    assert empty.exit_code != 0
    assert oversized.exit_code != 0
    assert not (tmp_path / "ldap_bind_password").exists()


def test_ca_helper_rejects_non_certificate_without_replacing_existing(tmp_path):
    from ldap_secret_cli import cli

    target = tmp_path / "ldap_ca.pem"
    target.write_text("existing-ca", encoding="utf-8")
    result = CliRunner().invoke(
        cli,
        ["--secret-dir", str(tmp_path), "install-ca", "--stdin"],
        input="not a certificate\n",
    )

    assert result.exit_code != 0
    assert target.read_text(encoding="utf-8") == "existing-ca"


def test_remove_helper_deletes_only_known_ldap_files(tmp_path):
    from ldap_secret_cli import cli

    for filename in ("ldap_bind_password", "ldap_ca.pem", "keep-me"):
        (tmp_path / filename).write_text(filename, encoding="utf-8")

    result = CliRunner().invoke(
        cli,
        ["--secret-dir", str(tmp_path), "remove", "--yes"],
    )

    assert result.exit_code == 0, result.output
    assert not (tmp_path / "ldap_bind_password").exists()
    assert not (tmp_path / "ldap_ca.pem").exists()
    assert (tmp_path / "keep-me").exists()
