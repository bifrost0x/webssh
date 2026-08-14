"""Generate a disposable CA and LDAP server certificate for the local lab."""

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


CERT_DIR = Path("/certs")
LDAP_UID = 911
LDAP_GID = 911


def _write(path, content, mode):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(content)
    os.chmod(temporary, mode)
    os.chown(temporary, LDAP_UID, LDAP_GID)
    os.replace(temporary, path)


def main():
    CERT_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
    certificate_paths = (
        CERT_DIR / "ca.crt",
        CERT_DIR / "cert.crt",
        CERT_DIR / "cert.key",
    )
    if all(
        path.is_file() and path.stat().st_size > 0
        for path in certificate_paths
    ):
        return
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "WebSSH LDAP Test CA"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=7))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "ldap.example.test"),
    ])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("ldap.example.test"),
            ]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    _write(
        CERT_DIR / "ca.crt",
        ca_cert.public_bytes(serialization.Encoding.PEM),
        0o644,
    )
    _write(
        CERT_DIR / "cert.crt",
        server_cert.public_bytes(serialization.Encoding.PEM),
        0o644,
    )
    _write(
        CERT_DIR / "cert.key",
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        0o600,
    )


if __name__ == "__main__":
    main()
