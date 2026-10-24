"""The product identity is local, accessible and shared by every full page."""

from pathlib import Path
import re
import xml.etree.ElementTree as ET

from app.static_delivery import static_asset_version
from tests.test_webssh2_shell import _create_login


def test_authentication_pages_ship_square_theme_aware_branding(app, client):
    _create_login(app, client)
    client.post('/logout')
    app.config['REGISTRATION_ENABLED'] = True
    for route in ('/login', '/register'):
        page = client.get(route)
        assert page.status_code == 200
        assert b'<svg class="auth-product-logo"' in page.data
        assert b'aria-label="WebSSH"' in page.data
        assert b'#webssh-terminal' in page.data
        assert b'rel="icon"' in page.data
        assert b'css/branding.css?v=' in page.data


def test_authenticated_surfaces_share_the_same_brand_symbol(app, client):
    _create_login(app, client)
    for route, logo_class in (
        ('/', 'app-brand-logo'),
        ('/settings', 'app-brand-logo'),
        ('/security', 'app-brand-logo'),
        ('/change-password', 'auth-product-logo'),
    ):
        page = client.get(route)
        assert page.status_code == 200
        assert f'<svg class="{logo_class}"'.encode() in page.data
        assert b'#webssh-terminal' in page.data
        assert b'rel="icon"' in page.data


def test_standalone_logo_is_safe_square_and_immutably_versioned(app, client):
    version = static_asset_version(app, 'images/webssh-logo.svg')
    response = client.get(f'/static/images/webssh-logo.svg?v={version}')
    assert response.status_code == 200
    assert response.mimetype == 'image/svg+xml'
    assert 'immutable' in response.headers['Cache-Control']
    root = ET.fromstring(response.data)
    assert root.attrib['viewBox'] == '0 0 128 128'
    assert root.attrib['id'] == 'webssh-terminal'
    assert not list(root.iter('{http://www.w3.org/2000/svg}text'))
    for element in root.iter():
        assert element.tag.rsplit('}', 1)[-1] not in ('script', 'foreignObject', 'image')
        assert not any(key.startswith('on') for key in element.attrib)
        assert not any('http' in value for value in element.attrib.values())


def test_static_site_and_readme_do_not_stretch_the_square_mark():
    root = Path(__file__).resolve().parents[1]
    for page in (root / 'site').glob('*.html'):
        contents = page.read_text(encoding='utf-8')
        for image in re.findall(r'<img[^>]+webssh-logo\.svg[^>]*>', contents):
            assert 'width="40"' in image and 'height="40"' in image
    assert 'width="128"' in (root / 'README.md').read_text(encoding='utf-8').split('</p>', 1)[0]
    assert 'src="static/images/webssh-logo.svg"' in (root / 'README.md').read_text(encoding='utf-8')
