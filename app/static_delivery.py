"""Safe delivery policy for public, application-owned static assets."""

import gzip
import hashlib
import mimetypes
import os
import re
from collections import OrderedDict
from functools import lru_cache, wraps
from pathlib import Path
from threading import Lock

from flask import request, url_for
from flask.sessions import SecureCookieSessionInterface


_VERSION_PATTERN = re.compile(r"[0-9a-f]{16}")
_COMPRESSIBLE_MIMETYPES = (
    "application/javascript",
    "application/x-javascript",
    "font/otf",
    "font/ttf",
    "image/svg+xml",
    "text/css",
    "text/javascript",
)
_ASSET_INDEX_EXTENSION = "static_delivery_asset_paths"
_DEFERRED_CONDITIONAL_ENV = "webssh.static_delivery.deferred_conditional"
_CONDITIONAL_ENV_KEYS = (
    "HTTP_IF_MATCH",
    "HTTP_IF_NONE_MATCH",
    "HTTP_IF_MODIFIED_SINCE",
    "HTTP_IF_UNMODIFIED_SINCE",
)


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


# Compressed bytes per opened file version (device, inode, mtime, ctime and
# size). Static files are public and the same for every request, so
# compressing them once avoids repeating the work on each hit, including
# conditional requests that end as 304. The index page alone loads well over
# a hundred compressible assets in a fixed order, so the cache holds more
# entries than that and is bounded by the compressed bytes it keeps.
_GZIP_CACHE_SIZE = 256
_GZIP_CACHE_MAX_BYTES = 4 * 1024 * 1024
_gzip_cache: "OrderedDict[tuple, tuple[bytes, int]]" = OrderedDict()
_gzip_cache_lock = Lock()


def _compressed_asset(identity, response) -> tuple[bytes, int]:
    with _gzip_cache_lock:
        cached = _gzip_cache.get(identity)
        if cached is not None:
            _gzip_cache.move_to_end(identity)
            return cached
    plain = response.get_data()
    entry = (gzip.compress(plain, compresslevel=6, mtime=0), len(plain))
    if len(plain) != identity[4]:
        # The handle did not deliver the whole file; do not keep the result.
        return entry
    if len(entry[0]) > _GZIP_CACHE_MAX_BYTES:
        return entry
    with _gzip_cache_lock:
        _gzip_cache[identity] = entry
        _gzip_cache.move_to_end(identity)
        cached_bytes = sum(len(data) for data, _length in _gzip_cache.values())
        while (
            len(_gzip_cache) > _GZIP_CACHE_SIZE
            or cached_bytes > _GZIP_CACHE_MAX_BYTES
        ):
            evicted, _length = _gzip_cache.popitem(last=False)[1]
            cached_bytes -= len(evicted)
    return entry


def _opened_file_identity(response):
    """Identity of the file the response body will be read from, or None.

    Taken with fstat from the already opened handle, so it always describes
    the bytes that are served, even if the path was replaced meanwhile.
    Werkzeug's wrapper exposes the handle as ``file``, Gunicorn's as
    ``filelike``.
    """
    wrapper = response.response
    handle = getattr(wrapper, "file", None) or getattr(wrapper, "filelike", None)
    try:
        stat = os.fstat(handle.fileno())
    except (AttributeError, OSError, ValueError):
        return None
    return stat.st_dev, stat.st_ino, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size


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

    # set_data replaces the file iterator without closing it, which reading
    # it through get_data used to arrange.
    identity = _opened_file_identity(response)
    file_close = getattr(response.response, "close", None)
    if callable(file_close):
        response.call_on_close(file_close)
    response.direct_passthrough = False
    if identity is None:
        plain = response.get_data()
        compressed, plain_length = gzip.compress(plain, compresslevel=6, mtime=0), len(plain)
    else:
        compressed, plain_length = _compressed_asset(identity, response)
    if len(compressed) >= plain_length:
        return response

    etag, weak = response.get_etag()
    if etag:
        response.set_etag(f"{etag}:gzip", weak=weak)
    response.set_data(compressed)
    response.headers["Content-Encoding"] = "gzip"
    response.headers["Content-Length"] = str(len(compressed))
    return response.make_conditional(request)


def _apply_deferred_static_condition(response):
    deferred = request.environ.pop(_DEFERRED_CONDITIONAL_ENV, False)
    if not deferred or response.status_code != 200:
        return response
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
    # Keep bundled media types deterministic across host MIME databases.
    mimetypes.add_type("image/webp", ".webp")
    for extension in ('woff2', 'woff', 'ttf', 'otf'):
        mimetypes.add_type('font/' + extension, '.' + extension)

    if not isinstance(app.session_interface, SecureCookieSessionInterface):
        raise RuntimeError(
            "static delivery requires Flask's secure-cookie session interface"
        )
    app.session_interface = _StaticAwareSessionInterface()
    app.extensions[_ASSET_INDEX_EXTENSION] = _build_static_asset_index(app)

    static_view = app.view_functions.get("static")
    if static_view is None:
        raise RuntimeError("static delivery requires Flask's static endpoint")

    @wraps(static_view)
    def serve_static_with_negotiated_conditionals(**values):
        deferred_headers = {}
        if (
            request.method in {"GET", "HEAD"}
            and "Range" not in request.headers
            and request.accept_encodings.best_match(("gzip", "identity")) == "gzip"
        ):
            for key in _CONDITIONAL_ENV_KEYS:
                value = request.environ.pop(key, None)
                if value is not None:
                    deferred_headers[key] = value
            if deferred_headers:
                request.environ[_DEFERRED_CONDITIONAL_ENV] = True
        try:
            return static_view(**values)
        finally:
            request.environ.update(deferred_headers)

    app.view_functions["static"] = serve_static_with_negotiated_conditionals

    def static_asset_url(filename: str) -> str:
        version = static_asset_version(app, filename)
        if version is None:
            raise FileNotFoundError(f"static asset does not exist: {filename}")
        return url_for("static", filename=filename, v=version)

    app.jinja_env.globals["static_asset_url"] = static_asset_url

    def translation_asset_urls() -> dict[str, str]:
        """Versioned URLs of the per-language files in static/js/i18n/."""
        prefix = "js/i18n/"
        return {
            path[len(prefix):-len(".js")]: static_asset_url(path)
            for path in sorted(app.extensions[_ASSET_INDEX_EXTENSION])
            if path.startswith(prefix)
            and path.endswith(".js")
            and "/" not in path[len(prefix):]
        }

    app.jinja_env.globals["translation_asset_urls"] = translation_asset_urls

    @app.after_request
    def optimize_static_delivery(response):
        if request.endpoint != "static":
            return response

        # Flask-Login checks its remember-cookie marker after every response,
        # which marks the session as accessed even though static content does
        # not depend on it. Remove that artificial variance for shared caches.
        _remove_cookie_variance(response)

        if response.mimetype in _COMPRESSIBLE_MIMETYPES:
            response = _compress_static_response(response)
        response = _apply_deferred_static_condition(response)

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
        return response
