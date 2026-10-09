"""Public, same-origin return paths for completed authentication."""
from urllib.parse import urlsplit

from flask import request

from .auth_assurance import _safe_continuation


def public_continuation(value):
    """Add the trusted request prefix once, preserving the query string."""
    candidate = _safe_continuation(value)
    prefix = request.script_root.rstrip('/')
    path = urlsplit(candidate).path
    # Browsers normalize literal and percent-encoded dot segments in URLs.
    if any(segment.lower().replace('%2e', '.') in {'.', '..'}
           for segment in path.split('/')):
        return prefix + '/'
    if not prefix or path == prefix or path.startswith(prefix + '/'):
        return candidate
    return prefix + candidate
