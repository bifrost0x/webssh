import gzip

from app.static_delivery import static_asset_version


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
