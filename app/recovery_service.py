"""Single-use recovery codes stored only as domain-separated hashes."""

import hashlib
import hmac
import secrets
from threading import Lock

from .models import RecoveryCode, db


_DOMAIN = b"webssh-recovery-code-v1\0"
_recovery_lock = Lock()


def _normalize(code):
    return "".join(str(code or "").upper().split())


def _hash(code):
    return hashlib.sha256(
        _DOMAIN + _normalize(code).encode("ascii", "ignore")
    ).digest()


def generate_codes(user_id, *, count=10):
    if type(count) is not int or not 1 <= count <= 20:
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
    with _recovery_lock:
        rows = RecoveryCode.query.filter_by(user_id=user_id).all()
        for row in rows:
            if not hmac.compare_digest(bytes(row.code_hash), candidate):
                continue
            db.session.delete(row)
            db.session.commit()
            return True
    return False
