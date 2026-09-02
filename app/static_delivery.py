"""Safe delivery policy for public, application-owned static assets."""

import gzip
import hashlib
import re
from functools import lru_cache
from pathlib import Path

from flask import request, url_for
from flask.sessions import SecureCookieSessionInterface


_VERSION_PATTERN = re.compile(r"[0-9a-f]{16}")
_COMPRESSIBLE_MIMETYPES = (
    "application/javascript",
    "application/x-javascript",
    "image/svg+xml",
    "text/css",
    "text/javascript",
)
_ASSET_INDEX_EXTENSION = "static_delivery_asset_paths"


def _remove_cookie_variance(response) -> None:
    response.vary = [
        value for value in response.vary
        if value.casefold() != "cookie"
    ]


def _add_accept_encoding_variance(response) -> None:
    if all(value.casefold() != "accept-encoding" for value in response.vary):
        response.vary = [*response.vary, "Accept-Encoding"]


def _build_static_asset_index(app) -> dict[str, Path]:
    """Index trusted files without joining request-controlled path segments."""
    if not app.static_folder:
        raise RuntimeError("static delivery requires an application static folder")
    try:
        static_root = Path(app.static_folder).resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("application static folder does not exist") from exc

    asset_paths = {}
    for candidate in static_root.rglob("*"):
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(static_root)
        except (OSError, ValueError):
            continue
        if resolved.is_file():
            asset_paths[candidate.relative_to(static_root).as_posix()] = resolved
    return asset_paths


@lru_cache(maxsize=512)
def _content_version(
    path: str,
    modified_ns: int,
    changed_ns: int,
    size: int,
) -> str:
    del modified_ns, changed_ns, size
    digest = hashlib.sha256()
    with open(path, "rb") as asset:
        for chunk in iter(lambda: asset.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()[:16]


def static_asset_version(app, filename: str) -> str | None:
    """Return a content-derived cache key for one local static asset."""
    asset_paths = app.extensions.get(_ASSET_INDEX_EXTENSION, {})
    asset_path = asset_paths.get(filename)
    if asset_path is None:
        return None
    try:
        stat = asset_path.stat()
        return _content_version(
            str(asset_path),
            stat.st_mtime_ns,
            stat.st_ctime_ns,
            stat.st_size,
        )
    except OSError:
        return None


def _compress_static_response(response):
    """Apply deterministic gzip with an encoding-specific validator."""
    _add_accept_encoding_variance(response)
    if (
        request.method not in {"GET", "HEAD"}
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


def _has_current_asset_version(app) -> bool:
    """Return whether the only query key matches the current asset content."""
    versions = request.args.getlist("v")
    if (
        len(request.args) != 1
        or len(versions) != 1
        or _VERSION_PATTERN.fullmatch(versions[0]) is None
    ):
        return False
    filename = (request.view_args or {}).get("filename")
    if not isinstance(filename, str):
        return False
    return versions[0] == static_asset_version(app, filename)


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
    app.extensions[_ASSET_INDEX_EXTENSION] = _build_static_asset_index(app)

    def static_asset_url(filename: str) -> str:
        version = static_asset_version(app, filename)
        if version is None:
            raise FileNotFoundError(f"static asset does not exist: {filename}")
        return url_for("static", filename=filename, v=version)

    app.jinja_env.globals["static_asset_url"] = static_asset_url

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
            and _has_current_asset_version(app)
        ):
            response.headers["Cache-Control"] = (
                "public, max-age=31536000, immutable"
            )
        elif request.method not in {"GET", "HEAD"} or request.args:
            response.headers["Cache-Control"] = "no-store"
        else:
            response.headers["Cache-Control"] = (
                "public, max-age=0, must-revalidate"
            )
        response.headers.pop("Pragma", None)
        response.headers.pop("Expires", None)

        if response.mimetype not in _COMPRESSIBLE_MIMETYPES:
            return response

        return _compress_static_response(response)
