"""Safe delivery policy for public, application-owned static assets."""

import gzip
import re

from flask import request
from flask.sessions import SecureCookieSessionInterface


_VERSION_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,64}")
_COMPRESSIBLE_MIMETYPES = (
    "application/javascript",
    "application/x-javascript",
    "image/svg+xml",
    "text/css",
    "text/javascript",
)


def _remove_cookie_variance(response) -> None:
    response.vary = [
        value for value in response.vary
        if value.casefold() != "cookie"
    ]


def _add_accept_encoding_variance(response) -> None:
    if all(value.casefold() != "accept-encoding" for value in response.vary):
        response.vary = [*response.vary, "Accept-Encoding"]


def _compress_static_response(response):
    """Apply deterministic gzip with an encoding-specific validator."""
    _add_accept_encoding_variance(response)
    if (
        request.method != "GET"
        or response.status_code != 200
        or "Content-Range" in response.headers
        or "Content-Encoding" in response.headers
        or request.accept_encodings.best_match(("gzip", "identity")) != "gzip"
        or (
            response.content_length is not None
            and response.content_length < 1024
        )
    ):
        return response

    response.direct_passthrough = False
    plain = response.get_data()
    compressed = gzip.compress(plain, compresslevel=6, mtime=0)
    if len(compressed) >= len(plain):
        return response

    etag, weak = response.get_etag()
    if etag:
        response.set_etag(f"{etag}:gzip", weak=weak)
    response.set_data(compressed)
    response.headers["Content-Encoding"] = "gzip"
    response.headers["Content-Length"] = str(len(compressed))
    return response.make_conditional(request)


class _StaticAwareSessionInterface(SecureCookieSessionInterface):
    """Remove artificial cookie variance after Flask saves the session."""

    def save_session(self, app, session, response) -> None:
        super().save_session(app, session, response)
        if request.endpoint != "static":
            return
        if response.headers.getlist("Set-Cookie"):
            response.headers["Cache-Control"] = "private, no-store"
        else:
            _remove_cookie_variance(response)


def _has_valid_asset_version() -> bool:
    """Return whether the request has exactly one bounded cache-version key."""
    versions = request.args.getlist("v")
    return (
        len(request.args) == 1
        and len(versions) == 1
        and _VERSION_PATTERN.fullmatch(versions[0]) is not None
    )


def init_static_delivery(app) -> None:
    """Enable compression and explicit caching only for Flask's static route.

    Dynamic HTML and API responses are deliberately excluded so secrets, CSRF
    tokens, and user-specific data never share a compression context.
    """
    if not isinstance(app.session_interface, SecureCookieSessionInterface):
        raise RuntimeError(
            "static delivery requires Flask's secure-cookie session interface"
        )
    app.session_interface = _StaticAwareSessionInterface()

    @app.after_request
    def optimize_static_delivery(response):
        if request.endpoint != "static":
            return response

        # Flask-Login checks its remember-cookie marker after every response,
        # which marks the session as accessed even though static content does
        # not depend on it. Remove that artificial variance for shared caches.
        _remove_cookie_variance(response)

        if response.headers.getlist("Set-Cookie"):
            response.headers["Cache-Control"] = "private, no-store"
        elif (
            request.method in {"GET", "HEAD"}
            and response.status_code in {200, 206, 304}
            and _has_valid_asset_version()
        ):
            response.headers["Cache-Control"] = (
                "public, max-age=31536000, immutable"
            )
        else:
            response.headers["Cache-Control"] = (
                "public, max-age=0, must-revalidate"
            )
        response.headers.pop("Pragma", None)
        response.headers.pop("Expires", None)

        if response.mimetype not in _COMPRESSIBLE_MIMETYPES:
            return response

        return _compress_static_response(response)
