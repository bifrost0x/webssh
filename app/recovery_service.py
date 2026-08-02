"""Single-use recovery codes stored only as domain-separated hashes."""

import hashlib
import hmac
import secrets
from threading import Lock

from .models import RecoveryCode, db


_DOMAIN = b"webssh-recovery-code-v1\0"
_DUMMY_KDF_SALT = b"webssh-recovery-verification-v1"
_DUMMY_KDF_ITERATIONS = 200_000
_MAX_RECOVERY_CODES = 20
_recovery_lock = Lock()


def _normalize(code):
    return "".join(str(code or "").upper().split())


def _hash(code):
    return hashlib.sha256(
        _DOMAIN + _normalize(code).encode("ascii", "ignore")
    ).digest()


_DUMMY_CODE_HASHES = tuple(
    _hash(f"dummy-recovery-code-{index}")
    for index in range(_MAX_RECOVERY_CODES)
)


def _equalize_verification_cost(candidate):
    """Perform fixed expensive work on every recovery-code verification."""
    hashlib.pbkdf2_hmac(
        "sha256",
        candidate,
        _DUMMY_KDF_SALT,
        _DUMMY_KDF_ITERATIONS,
        dklen=32,
    )


def generate_codes(user_id, *, count=10):
    if type(count) is not int or not 1 <= count <= _MAX_RECOVERY_CODES:
        raise ValueError("Recovery code count must be between 1 and 20")
    with _recovery_lock:
        RecoveryCode.query.filter_by(user_id=user_id).delete()
        plaintext = []
        for _ in range(count):
            raw = secrets.token_hex(10).upper()
            code = "-".join(
                raw[index:index + 4] for index in range(0, 20, 4)
            )
            plaintext.append(
                code
            )
            db.session.add(
                RecoveryCode(user_id=user_id, code_hash=_hash(code))
            )
        db.session.commit()
    return plaintext


def consume_code(user_id, code):
    candidate = _hash(code)
    _equalize_verification_cost(candidate)
    with _recovery_lock:
        query_user_id = user_id if user_id is not None else -1
        rows = RecoveryCode.query.filter_by(
            user_id=query_user_id
        ).limit(_MAX_RECOVERY_CODES).all()
        matched_row = None
        for index in range(_MAX_RECOVERY_CODES):
            row = rows[index] if index < len(rows) else None
            expected = (
                bytes(row.code_hash)
                if row is not None
                else _DUMMY_CODE_HASHES[index]
            )
            if hmac.compare_digest(expected, candidate) and row is not None:
                matched_row = row
        if matched_row is not None:
            db.session.delete(matched_row)
            db.session.commit()
            return True
    return False
