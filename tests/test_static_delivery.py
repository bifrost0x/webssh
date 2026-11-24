import gzip
import pytest

from app.static_delivery import static_asset_version


@pytest.mark.parametrize('extension,content_type', [
    ('.woff2', 'font/woff2'), ('.woff', 'font/woff'),
    ('.ttf', 'font/ttf'), ('.otf', 'font/otf'),
])
def test_font_mime_registration_overrides_incorrect_host_mapping(monkeypatch, tmp_path, extension, content_type):
    import mimetypes
    from flask import Flask
    from app.static_delivery import init_static_delivery

    mimetypes.init()
    monkeypatch.setitem(mimetypes.types_map, extension, 'application/octet-stream')
    (tmp_path / ('font' + extension)).write_bytes(b'font-test-bytes')
    app = Flask('font_mime_test', static_folder=str(tmp_path), static_url_path='/static')
    init_static_delivery(app)
    response = app.test_client().get('/static/font' + extension)
    assert response.status_code == 200
    assert response.mimetype == content_type
    assert response.data == b'font-test-bytes'


def _asset_url(client, filename):
    version = static_asset_version(client.application, filename)
    assert version is not None
    return f'/static/{filename}?v={version}'


def test_versioned_static_text_is_publicly_cached_and_compressed(client):
    response = client.get(
        _asset_url(client, 'js/i18n-auth.js'),
        headers={'Accept-Encoding': 'br, gzip'},
    )

    assert response.status_code == 200
    assert response.headers['Cache-Control'] == (
        'public, max-age=31536000, immutable'
    )
    assert response.headers['Content-Encoding'] == 'gzip'
    assert 'Accept-Encoding' in response.headers['Vary']
    assert 'Cookie' not in response.headers['Vary']
    assert b'const translations' in gzip.decompress(response.data)
    assert response.headers['Content-Security-Policy'].startswith("default-src 'self'")


def test_static_compression_has_encoding_specific_conditional_etags(client):
    target = _asset_url(client, 'js/i18n-auth.js')
    compressed = client.get(
        target,
        headers={'Accept-Encoding': 'gzip'},
    )
    plain = client.get(target)

    assert compressed.headers['Content-Encoding'] == 'gzip'
    assert compressed.headers['ETag'] != plain.headers['ETag']

    unchanged = client.get(
        target,
        headers={
            'Accept-Encoding': 'gzip',
            'If-None-Match': compressed.headers['ETag'],
        },
    )
    assert unchanged.status_code == 304
    assert unchanged.headers['Cache-Control'] == (
        'public, max-age=31536000, immutable'
    )

    identity_validator = client.get(
        target,
        headers={
            'Accept-Encoding': 'gzip, identity;q=0',
            'If-None-Match': plain.headers['ETag'],
        },
    )
    assert identity_validator.status_code == 200
    assert identity_validator.headers['Content-Encoding'] == 'gzip'
    assert identity_validator.headers['ETag'] == compressed.headers['ETag']
    assert gzip.decompress(identity_validator.data) == plain.data

    failed_precondition = client.get(
        target,
        headers={
            'Accept-Encoding': 'gzip',
            'If-Match': '"not-the-current-representation"',
        },
    )
    assert failed_precondition.status_code == 412
    assert failed_precondition.headers['Cache-Control'] == 'no-store'


def test_unversioned_static_urls_must_revalidate(client):
    response = client.get('/static/js/i18n-auth.js')

    assert response.status_code == 200
    assert response.headers['Cache-Control'] == (
        'public, max-age=0, must-revalidate'
    )


def test_untrusted_static_query_strings_are_not_stored(client):
    current_version = static_asset_version(client.application, 'js/i18n-auth.js')
    assert current_version is not None
    wrong_version = '0' * 16
    assert wrong_version != current_version
    for target in (
        '/static/js/i18n-auth.js?v=',
        f'/static/js/i18n-auth.js?v={current_version}&v={current_version}',
        f'/static/js/i18n-auth.js?v={current_version}&download=1',
        '/static/js/i18n-auth.js?v=unsafe%20value',
        f'/static/js/i18n-auth.js?v={wrong_version}',
    ):
        response = client.get(target)
        assert response.status_code == 200
        assert response.headers['Cache-Control'] == 'no-store'


def test_missing_versioned_asset_is_not_immutably_cached(client):
    response = client.get('/static/js/does-not-exist.js?v=0000000000000000')

    assert response.status_code == 404
    assert response.headers['Cache-Control'] == 'no-store'


def test_asset_versions_never_resolve_paths_outside_the_static_index(client):
    assert static_asset_version(client.application, '../app/__init__.py') is None
    assert static_asset_version(client.application, '/etc/passwd') is None


def test_static_encoding_negotiation_respects_client_quality(client):
    target = _asset_url(client, 'js/i18n-auth.js')
    brotli_only = client.get(
        target,
        headers={'Accept-Encoding': 'br'},
    )
    disabled_gzip = client.get(
        target,
        headers={'Accept-Encoding': 'gzip;q=0, identity;q=1'},
    )

    assert 'Content-Encoding' not in brotli_only.headers
    assert 'Content-Encoding' not in disabled_gzip.headers
    assert 'Accept-Encoding' in brotli_only.headers['Vary']


def test_ranges_and_non_text_assets_are_not_compressed(client):
    partial = client.get(
        _asset_url(client, 'js/i18n-auth.js'),
        headers={
            'Accept-Encoding': 'br, gzip',
            'Range': 'bytes=0-63',
        },
    )
    image = client.get(
        _asset_url(client, 'images/theme-backgrounds/carbon-glass.png'),
        headers={'Accept-Encoding': 'br, gzip'},
    )

    assert partial.status_code == 206
    assert partial.headers['Content-Range'].startswith('bytes 0-63/')
    assert 'Content-Encoding' not in partial.headers
    assert image.status_code == 200
    assert 'Content-Encoding' not in image.headers


def test_static_head_matches_the_selected_get_representation(client):
    target = _asset_url(client, 'js/i18n-auth.js')
    static_get = client.get(
        target,
        headers={'Accept-Encoding': 'br, gzip'},
    )
    static_head = client.head(
        target,
        headers={'Accept-Encoding': 'br, gzip'},
    )

    assert static_head.status_code == 200
    assert static_head.data == b''
    for header in ('Content-Encoding', 'Content-Length', 'ETag', 'Vary', 'Cache-Control'):
        assert static_head.headers[header] == static_get.headers[header]


def test_dynamic_html_is_not_compressed(client):
    login = client.get(
        '/login',
        headers={'Accept-Encoding': 'br, gzip'},
        follow_redirects=True,
    )

    assert login.status_code == 200
    assert login.mimetype == 'text/html'
    assert 'Content-Encoding' not in login.headers


def test_static_options_response_is_not_immutably_cached(client):
    response = client.open(
        _asset_url(client, 'js/i18n-auth.js'),
        method='OPTIONS',
    )

    assert response.status_code == 200
    assert response.headers['Cache-Control'] == 'no-store'
    assert 'Content-Encoding' not in response.headers


def test_static_requests_do_not_open_an_existing_login_session(client):
    with client.session_transaction() as browser_session:
        browser_session['_user_id'] = 'nonexistent-user'
        browser_session['_fresh'] = True

    response = client.get(_asset_url(client, 'css/style.css'))

    assert response.status_code == 200
    assert 'Cookie' not in response.headers.get('Vary', '')
    assert 'Set-Cookie' not in response.headers


def test_static_response_with_an_auth_cookie_mutation_is_never_public(client):
    with client.session_transaction() as browser_session:
        browser_session['_user_id'] = '1'
        browser_session['_remember'] = 'set'

    response = client.get(_asset_url(client, 'css/style.css'))

    assert response.status_code == 200
    assert response.headers['Cache-Control'] == 'private, no-store'
    assert response.headers.getlist('Set-Cookie')


def test_webp_backgrounds_keep_image_headers_and_cache_validators(client):
    from pathlib import Path

    assets = sorted(Path('static/images/theme-backgrounds').glob('*.webp'))
    assert len(assets) == 10
    scenes = sorted(Path('static/images/theme-scenes').glob('*.webp'))
    assert len(scenes) == 10
    assets.extend(scenes)
    for asset in assets:
        target = _asset_url(client, asset.relative_to('static').as_posix())
        response = client.get(target, headers={'Accept-Encoding': 'gzip'})
        assert response.status_code == 200
        assert response.mimetype == 'image/webp'
        assert response.data == asset.read_bytes()
        assert 'Content-Encoding' not in response.headers
        assert response.headers['Cache-Control'] == 'public, max-age=31536000, immutable'
        assert response.headers['X-Content-Type-Options'] == 'nosniff'
        assert 'Set-Cookie' not in response.headers
        assert 'Cookie' not in response.headers.get('Vary', '')
        cached = client.get(target, headers={'If-None-Match': response.headers['ETag']})
        assert cached.status_code == 304
        assert cached.data == b''
        head = client.head(target)
        assert head.status_code == 200
        assert head.content_length == len(response.data)
        assert head.data == b''


def test_webp_mime_registration_overrides_an_incorrect_host_mapping(monkeypatch, tmp_path):
    import mimetypes
    from flask import Flask
    from app.static_delivery import init_static_delivery

    mimetypes.init()
    monkeypatch.setitem(mimetypes.types_map, '.webp', 'application/octet-stream')
    (tmp_path / 'background.webp').write_bytes(b'RIFF\x00\x00\x00\x00WEBP')
    app = Flask('webp_mime_test', static_folder=str(tmp_path), static_url_path='/static')
    init_static_delivery(app)
    response = app.test_client().get('/static/background.webp')
    assert response.status_code == 200
    assert response.mimetype == 'image/webp'


def test_static_compression_is_computed_once_per_asset_version(client, monkeypatch):
    from app import static_delivery

    calls = []
    real_compress = gzip.compress

    def counting_compress(data, *args, **kwargs):
        calls.append(len(data))
        return real_compress(data, *args, **kwargs)

    monkeypatch.setattr(static_delivery.gzip, 'compress', counting_compress)
    static_delivery._gzip_cache.clear()
    plain = client.get('/static/js/i18n.js', headers={'Accept-Encoding': 'identity'})
    head = client.head('/static/js/i18n.js', headers={'Accept-Encoding': 'gzip'})
    first = client.get('/static/js/i18n.js', headers={'Accept-Encoding': 'gzip'})
    second = client.get('/static/js/i18n.js', headers={'Accept-Encoding': 'gzip'})
    revalidated = client.get('/static/js/i18n.js', headers={
        'Accept-Encoding': 'gzip',
        'If-None-Match': first.headers['ETag'],
    })

    assert len(calls) == 1
    assert head.headers['Content-Encoding'] == 'gzip'
    assert head.headers['Content-Length'] == first.headers['Content-Length']
    assert first.data == second.data
    assert gzip.decompress(first.data) == plain.data
    assert first.headers['ETag'] == second.headers['ETag']
    assert revalidated.status_code == 304


def test_cache_key_is_the_identity_of_the_opened_file(app, client):
    import os
    from app import static_delivery

    static_delivery._gzip_cache.clear()
    asset_path = app.extensions[static_delivery._ASSET_INDEX_EXTENSION]['js/i18n.js']

    client.get('/static/js/i18n.js', headers={'Accept-Encoding': 'gzip'})

    with open(asset_path, 'rb') as handle:
        stat = os.fstat(handle.fileno())
    assert list(static_delivery._gzip_cache) == [
        (stat.st_dev, stat.st_ino, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size),
    ]


def test_another_file_version_is_compressed_again(client, monkeypatch):
    # A file replaced on disk is a new inode or timestamp; the bytes cached for
    # the old version must not be served for it.
    from app import static_delivery

    static_delivery._gzip_cache.clear()
    real_identity = static_delivery._opened_file_identity
    first = client.get('/static/js/i18n.js', headers={'Accept-Encoding': 'gzip'})
    old_identity = next(iter(static_delivery._gzip_cache))
    static_delivery._gzip_cache[old_identity] = (b'stale', 1)
    monkeypatch.setattr(
        static_delivery, '_opened_file_identity',
        lambda response: real_identity(response)[:2] + (old_identity[2] + 1,) + old_identity[3:],
    )

    second = client.get('/static/js/i18n.js', headers={'Accept-Encoding': 'gzip'})

    assert second.data == first.data


def test_a_response_without_an_open_file_is_not_cached(client, monkeypatch):
    from app import static_delivery

    static_delivery._gzip_cache.clear()
    monkeypatch.setattr(static_delivery, '_opened_file_identity', lambda response: None)

    response = client.get('/static/js/i18n.js', headers={'Accept-Encoding': 'gzip'})

    assert response.headers['Content-Encoding'] == 'gzip'
    assert static_delivery._gzip_cache == {}


def test_index_assets_stay_compressed_across_a_cold_page_load(app, client, monkeypatch):
    # The index page loads its compressible assets in one fixed order. With
    # an LRU smaller than that set, every load evicted what the next one
    # needed and nothing was ever served from the cache.
    from app import static_delivery

    asset_paths = app.extensions[static_delivery._ASSET_INDEX_EXTENSION]
    compressible = sorted(
        name for name, path in asset_paths.items()
        if path.suffix in {'.js', '.css', '.svg', '.ttf'}
        and path.stat().st_size >= 1024
    )
    assert len(compressible) > 64

    calls = []
    real_compress = gzip.compress

    def counting_compress(data, *args, **kwargs):
        calls.append(len(data))
        return real_compress(data, *args, **kwargs)

    monkeypatch.setattr(static_delivery.gzip, 'compress', counting_compress)
    static_delivery._gzip_cache.clear()
    for _load in range(2):
        for name in compressible:
            response = client.get(
                f'/static/{name}', headers={'Accept-Encoding': 'gzip'},
            )
            assert response.status_code == 200
    static_delivery._gzip_cache.clear()

    assert len(calls) == len(compressible)


def test_compressed_asset_cache_is_bounded_by_bytes(monkeypatch):
    from types import SimpleNamespace
    from app import static_delivery

    monkeypatch.setattr(static_delivery, '_GZIP_CACHE_MAX_BYTES', 1000)
    monkeypatch.setattr(static_delivery, '_GZIP_CACHE_SIZE', 100)
    monkeypatch.setattr(
        static_delivery.gzip, 'compress',
        lambda data, **_kwargs: b'z' * (len(data) // 2),
    )
    static_delivery._gzip_cache.clear()

    def compress(index, size):
        response = SimpleNamespace(get_data=lambda: b'p' * size)
        return static_delivery._compressed_asset(
            (1, index, 0, 0, size), response,
        )

    try:
        for index in range(5):
            compress(index, 400)
        assert sum(len(data) for data, _length in static_delivery._gzip_cache.values()) <= 1000
        assert [key[1] for key in static_delivery._gzip_cache] == [0, 1, 2, 3, 4]

        compress(5, 1000)
        assert [key[1] for key in static_delivery._gzip_cache] == [3, 4, 5]
        assert sum(len(data) for data, _length in static_delivery._gzip_cache.values()) <= 1000

        # An entry larger than the whole budget is served but never cached.
        result = compress(6, 4000)
        assert len(result[0]) == 2000
        assert 6 not in [key[1] for key in static_delivery._gzip_cache]
    finally:
        static_delivery._gzip_cache.clear()


def test_bundled_ttf_fonts_are_served_compressed(client):
    plain = client.get(
        '/static/vendor/roboto/Roboto-Variable.ttf',
        headers={'Accept-Encoding': 'identity'},
    )
    compressed = client.get(
        '/static/vendor/roboto/Roboto-Variable.ttf',
        headers={'Accept-Encoding': 'gzip'},
    )

    assert compressed.status_code == 200
    assert compressed.mimetype == 'font/ttf'
    assert compressed.headers['Content-Encoding'] == 'gzip'
    assert 'Accept-Encoding' in compressed.headers['Vary']
    assert len(compressed.data) < len(plain.data)
    assert gzip.decompress(compressed.data) == plain.data
    assert compressed.headers['ETag'] != plain.headers['ETag']
