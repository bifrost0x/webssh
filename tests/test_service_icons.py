"""Service logos: plain CC0 Simple Icons files with provenance and versioned URLs."""

import hashlib
import json
import re
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from app import host_catalog as c

ROOT = Path(__file__).parents[1]
DIRECTORY = ROOT / 'static' / 'icons' / 'services'


def _icons():
    return {path.stem: path for path in DIRECTORY.glob('*.svg')}


def _provenance():
    return json.loads((DIRECTORY / 'provenance.json').read_text(encoding='utf-8'))


def _create_login(app, client):
    from app.auth import register_user
    from app.models import db

    with app.app_context():
        user, error = register_user('service_icon_user', 'password123')
        assert error is None
        db.session.commit()
    assert client.post('/login', data={'username': 'service_icon_user', 'password': 'password123'}).status_code == 302


def test_service_logos_belong_to_catalog_services_and_are_recorded():
    icons = _icons()
    provenance = _provenance()
    assert icons, 'no service logos are bundled'
    assert set(icons) <= c.SERVICES
    assert set(icons) == set(provenance['icons'])
    assert provenance['version'] == '16.0.0'


def test_service_logos_are_cc0_only():
    provenance = _provenance()
    assert provenance['license'] == 'CC0-1.0'
    for name, entry in provenance['icons'].items():
        assert 'license' not in entry, name
        assert entry['slug'] and entry['title'] and entry['source'], name
    license_text = (DIRECTORY / 'LICENSE.md').read_text(encoding='utf-8')
    assert license_text.startswith('# CC0 1.0 Universal')


def test_service_logos_are_plain_simple_icons():
    provenance = _provenance()
    for name, path in _icons().items():
        svg = path.read_text(encoding='utf-8')
        title = provenance['icons'][name]['title'].replace('&', '&amp;')
        assert svg.startswith(f'<svg role="img" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><title>{title}</title><path d="'), name
        assert svg.endswith('"/></svg>') and svg.count('<') == 5, name


def test_licensing_lists_the_service_logos():
    licensing = (ROOT / 'docs' / 'licensing.md').read_text(encoding='utf-8')
    row = next((line for line in licensing.splitlines() if line.startswith('| Simple Icons service logos')), '')
    assert '(CC0-1.0)' in row
    assert '`static/icons/services/LICENSE.md`' in row and '`static/icons/services/provenance.json`' in row


def test_service_icons_have_content_addressed_urls(app, client):
    _create_login(app, client)
    source = client.get('/').get_data(as_text=True)
    manifest = re.search(r'<script id="hostServiceAssets" type="application/json">(.*?)</script>', source, re.S)
    assert manifest, 'Service logos need individually versioned asset URLs'
    assets = json.loads(manifest.group(1))
    expected = _icons()
    assert set(assets) == set(expected)
    for name, path in expected.items():
        parsed = urlsplit(assets[name])
        assert parsed.path.endswith(f'/static/icons/services/{name}.svg')
        assert parse_qs(parsed.query) == {'v': [hashlib.sha256(path.read_bytes()).hexdigest()[:16]]}
        assert client.get(assets[name]).data == path.read_bytes()
