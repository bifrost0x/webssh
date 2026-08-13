"""Opaque browser-storage namespaces for authenticated users."""

import hashlib
import hmac


def connection_history_scope(user, secret_key):
    """Return an instance-bound namespace for one generation of an account."""
    created_at = getattr(user, 'created_at', None)
    if created_at is not None:
        generation = created_at.isoformat()
    else:
        # Older imported databases can contain a null creation timestamp. The
        # salted password hash still prevents a reused numeric id from inheriting
        # browser history. A password change safely starts a fresh history.
        generation = getattr(user, 'password_hash', '')
    material = '\0'.join((
        'webssh-connection-history-v1',
        str(user.id),
        str(getattr(user, 'username', '')),
        generation,
    )).encode('utf-8')
    key = secret_key if isinstance(secret_key, bytes) else str(secret_key).encode('utf-8')
    return hmac.new(key, material, hashlib.sha256).hexdigest()
