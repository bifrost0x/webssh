"""Whether a request reached WebSSH from a page the browser loaded over HTTPS."""

from urllib.parse import urlsplit

from flask import request

_DEFAULT_PORTS = {'https': '443', 'http': '80'}


def _authority(value, scheme):
    """Lower-case host[:port] with the scheme's default port removed."""
    value = (value or '').strip().lower()
    port = _DEFAULT_PORTS.get(scheme)
    if port and value.endswith(':' + port) and not value.endswith(']'):
        value = value[:-(len(port) + 1)]
    return value


def request_reached_over_https(req=None):
    """True when the user's browser talked to WebSSH over HTTPS.

    Direct TLS, or a proxy trusted through TRUSTED_PROXIES, sets is_secure.
    Many installations put a TLS-terminating reverse proxy in front without
    configuring proxy trust (the default compose file sets TRUSTED_PROXIES=0),
    so WebSSH itself only sees plain HTTP from the proxy. The browser still
    states which page sent the request: Origin, or the Referer that the
    strict-origin-when-cross-origin policy keeps for same-origin requests.
    Page scripts cannot set either. A page served over https:// from the same
    host the request names means the user's connection was encrypted; a page
    opened over http://, from another host, or no stated page does not count.
    """
    req = req or request
    if req.is_secure:
        return True
    origin = req.headers.get('Origin', '')
    source = origin if origin and origin != 'null' else req.headers.get('Referer', '')
    try:
        parsed = urlsplit(source)
    except ValueError:
        return False
    if parsed.scheme != 'https' or not parsed.netloc or parsed.username or parsed.password:
        return False
    host = req.headers.get('Host', '')
    return bool(host) and _authority(parsed.netloc, 'https') == _authority(host, 'https')
