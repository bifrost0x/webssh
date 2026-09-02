import gzip


def test_versioned_static_text_is_publicly_cached_and_compressed(client):
    response = client.get(
        '/static/js/i18n-auth.js?v=1',
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
    compressed = client.get(
        '/static/js/i18n-auth.js?v=1',
        headers={'Accept-Encoding': 'gzip'},
    )
    plain = client.get('/static/js/i18n-auth.js?v=1')

    assert compressed.headers['Content-Encoding'] == 'gzip'
    assert compressed.headers['ETag'] != plain.headers['ETag']

    unchanged = client.get(
        '/static/js/i18n-auth.js?v=1',
        headers={
            'Accept-Encoding': 'gzip',
            'If-None-Match': compressed.headers['ETag'],
        },
    )
    assert unchanged.status_code == 304
    assert unchanged.headers['Cache-Control'] == (
        'public, max-age=31536000, immutable'
    )


def test_unversioned_or_ambiguous_static_urls_must_revalidate(client):
    for target in (
        '/static/js/i18n-auth.js',
        '/static/js/i18n-auth.js?v=',
        '/static/js/i18n-auth.js?v=1&v=2',
        '/static/js/i18n-auth.js?v=1&download=1',
        '/static/js/i18n-auth.js?v=unsafe%20value',
    ):
        response = client.get(target)
        assert response.status_code == 200
        assert response.headers['Cache-Control'] == (
            'public, max-age=0, must-revalidate'
        )


def test_missing_versioned_asset_is_not_immutably_cached(client):
    response = client.get('/static/js/does-not-exist.js?v=1')

    assert response.status_code == 404
    assert response.headers['Cache-Control'] == (
        'public, max-age=0, must-revalidate'
    )


def test_static_encoding_negotiation_respects_client_quality(client):
    brotli_only = client.get(
        '/static/js/i18n-auth.js?v=1',
        headers={'Accept-Encoding': 'br'},
    )
    disabled_gzip = client.get(
        '/static/js/i18n-auth.js?v=1',
        headers={'Accept-Encoding': 'gzip;q=0, identity;q=1'},
    )

    assert 'Content-Encoding' not in brotli_only.headers
    assert 'Content-Encoding' not in disabled_gzip.headers
    assert 'Accept-Encoding' in brotli_only.headers['Vary']


def test_ranges_and_non_text_assets_are_not_compressed(client):
    partial = client.get(
        '/static/js/i18n-auth.js?v=1',
        headers={
            'Accept-Encoding': 'br, gzip',
            'Range': 'bytes=0-63',
        },
    )
    image = client.get(
        '/static/images/theme-backgrounds/carbon-glass.png?v=1',
        headers={'Accept-Encoding': 'br, gzip'},
    )

    assert partial.status_code == 206
    assert partial.headers['Content-Range'].startswith('bytes 0-63/')
    assert 'Content-Encoding' not in partial.headers
    assert image.status_code == 200
    assert 'Content-Encoding' not in image.headers


def test_head_and_dynamic_html_are_not_compressed(client):
    static_head = client.head(
        '/static/js/i18n-auth.js?v=1',
        headers={'Accept-Encoding': 'br, gzip'},
    )
    login = client.get(
        '/login',
        headers={'Accept-Encoding': 'br, gzip'},
        follow_redirects=True,
    )

    assert static_head.status_code == 200
    assert 'Content-Encoding' not in static_head.headers
    assert login.status_code == 200
    assert login.mimetype == 'text/html'
    assert 'Content-Encoding' not in login.headers


def test_static_options_response_is_not_immutably_cached(client):
    response = client.open('/static/js/i18n-auth.js?v=1', method='OPTIONS')

    assert response.status_code == 200
    assert response.headers['Cache-Control'] == (
        'public, max-age=0, must-revalidate'
    )
    assert 'Content-Encoding' not in response.headers


def test_static_requests_do_not_open_an_existing_login_session(client):
    with client.session_transaction() as browser_session:
        browser_session['_user_id'] = 'nonexistent-user'
        browser_session['_fresh'] = True

    response = client.get('/static/css/style.css?v=25')

    assert response.status_code == 200
    assert 'Cookie' not in response.headers.get('Vary', '')
    assert 'Set-Cookie' not in response.headers


def test_static_response_with_an_auth_cookie_mutation_is_never_public(client):
    with client.session_transaction() as browser_session:
        browser_session['_user_id'] = '1'
        browser_session['_remember'] = 'set'

    response = client.get('/static/css/style.css?v=25')

    assert response.status_code == 200
    assert response.headers['Cache-Control'] == 'private, no-store'
    assert response.headers.getlist('Set-Cookie')
