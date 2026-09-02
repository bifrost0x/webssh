import re
from pathlib import Path


def test_direct_template_static_references_are_cache_versioned():
    missing_versions = []
    pattern = re.compile(
        r"url_for\('static',\s*filename='([^']+)'\)\s*\}\}([^\"']*)"
    )

    for template_path in sorted(Path('templates').glob('*.html')):
        source = template_path.read_text(encoding='utf-8')
        for asset, suffix in pattern.findall(source):
            if not re.fullmatch(r'\?v=[A-Za-z0-9._-]{1,64}', suffix):
                missing_versions.append(f'{template_path}:{asset}')

    assert missing_versions == []


def test_local_css_asset_references_are_cache_versioned():
    missing_versions = []
    pattern = re.compile(r'url\(["\']?([^"\')]+)')

    for stylesheet in sorted(Path('static/css').glob('*.css')):
        source = stylesheet.read_text(encoding='utf-8')
        for target in pattern.findall(source):
            if target.startswith(('data:', '#')):
                continue
            if '?v=' not in target:
                missing_versions.append(f'{stylesheet}:{target}')

    assert missing_versions == []


def test_auth_pages_use_the_generated_authentication_translation_bundle():
    for template_name in ('login.html', 'register.html', 'change_password.html'):
        source = (Path('templates') / template_name).read_text(encoding='utf-8')
        assert "filename='js/i18n-auth.js'" in source
        assert "filename='js/i18n.js'" not in source
        assert 'data-defer-theme-background' in source
        assert "filename='js/theme-preference.js'" in source


def test_authentication_translation_bundle_stays_within_its_page_load_budget():
    auth_size = Path('static/js/i18n-auth.js').stat().st_size
    full_size = Path('static/js/i18n.js').stat().st_size

    assert auth_size < 100_000
    assert auth_size < full_size * 0.2
