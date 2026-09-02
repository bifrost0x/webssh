import hashlib
import re
from pathlib import Path
from urllib.parse import parse_qs


def test_direct_template_static_references_use_content_addressed_urls():
    invalid_references = []
    pattern = re.compile(r"static_asset_url\(filename='([^']+)'\)")
    legacy_pattern = re.compile(r"url_for\('static'")
    reference_count = 0

    for template_path in sorted(Path('templates').glob('*.html')):
        source = template_path.read_text(encoding='utf-8')
        if legacy_pattern.search(source):
            invalid_references.append(f'{template_path}:legacy-url-for')
        for asset in pattern.findall(source):
            reference_count += 1
            if not (Path('static') / asset).is_file():
                invalid_references.append(f'{template_path}:{asset}')

    assert reference_count > 0
    assert invalid_references == []


def test_local_css_asset_references_use_current_content_hashes():
    invalid_versions = []
    pattern = re.compile(r'url\(["\']?([^"\')]+)')

    for stylesheet in sorted(Path('static/css').glob('*.css')):
        source = stylesheet.read_text(encoding='utf-8')
        for target in pattern.findall(source):
            if target.startswith(('data:', '#', 'http://', 'https://')):
                continue
            relative_path, separator, query = target.partition('?')
            params = parse_qs(query, keep_blank_values=True)
            asset_path = (stylesheet.parent / relative_path).resolve()
            if (
                not separator
                or set(params) != {'v'}
                or len(params['v']) != 1
                or not asset_path.is_file()
            ):
                invalid_versions.append(f'{stylesheet}:{target}')
                continue
            expected = hashlib.sha256(asset_path.read_bytes()).hexdigest()[:16]
            if params['v'][0] != expected:
                invalid_versions.append(f'{stylesheet}:{target}')

    assert invalid_versions == []


def test_auth_pages_use_the_generated_authentication_translation_bundle():
    for template_name in ('login.html', 'register.html', 'change_password.html'):
        source = (Path('templates') / template_name).read_text(encoding='utf-8')
        assert "static_asset_url(filename='js/i18n-auth.js')" in source
        assert "static_asset_url(filename='js/i18n.js')" not in source
        assert 'data-defer-theme-background' in source
        assert "static_asset_url(filename='js/theme-preference.js')" in source


def test_authentication_translation_bundle_stays_within_its_page_load_budget():
    auth_size = Path('static/js/i18n-auth.js').stat().st_size
    full_size = Path('static/js/i18n.js').stat().st_size

    assert auth_size < 100_000
    assert auth_size < full_size * 0.2
