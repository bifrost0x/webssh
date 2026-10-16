"""Public contracts for the GitHub Pages artifact."""

import base64
import hashlib
import importlib.util
import json
from html.parser import HTMLParser
from pathlib import Path
import shutil
from urllib.parse import unquote, urlsplit
from xml.etree import ElementTree

import pytest


ROOT = Path(__file__).resolve().parents[1]
PAGES_WORKFLOW = ROOT / '.github/workflows/graph-pages.yml'
LANDING_PAGE = ROOT / 'site/index.html'


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.tags = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

    def links(self):
        return {attrs.get('href') for tag, attrs in self.tags if tag == 'a'}


def packager():
    path = ROOT / 'scripts/prepare_pages.py'
    assert path.is_file(), 'Missing reproducible Pages packager'
    spec = importlib.util.spec_from_file_location('prepare_pages', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def built_site(tmp_path):
    graph = tmp_path / 'graph.html'
    graph.write_text('''<!doctype html><html><head><title>Code graph</title>
<script src="https://unpkg.com/vis-network@9.1.6/standalone/umd/vis-network.min.js" integrity="sha384-Ux6phic9PEHJ38YtrijhkzyJ8yQlH8i/+buBR8s3mAZOJrP1gwyvAcIYl3GWtpX1"></script>
<style>#sidebar { width: 280px; }</style></head><body><div id="graph"></div>
<input type="checkbox" id="select-all-cb" checked onchange="toggleAllCommunities(!this.checked)">
<script>window.graphReady = true;</script></body></html>''', encoding='utf-8')
    output = tmp_path / 'public'
    packager().prepare_pages(ROOT, graph, output)
    return output


def test_pages_workflow_publishes_product_root_and_code_graph_subpath():
    assert 'python scripts/prepare_pages.py' in PAGES_WORKFLOW.read_text(encoding='utf-8')


def test_code_graph_excludes_vendored_runtime_dependencies():
    patterns = set((ROOT / '.graphifyignore').read_text(encoding='utf-8').splitlines())
    assert '/static/vendor/' in patterns
    assert '/site/vendor/' in patterns


def test_product_landing_page_uses_current_connection_terminology():
    text = LANDING_PAGE.read_text(encoding='utf-8')
    for obsolete_label in ('New Connection', 'New SSH Connection', 'Profiles'):
        assert obsolete_label not in text


@pytest.mark.parametrize('page_name', ['index.html', 'features.html', 'self-hosting.html', 'security.html', 'impressum.html', 'privacy.html', 'code-graph/index.html'])
def test_packaged_pages_have_reachable_legal_links_and_local_assets(built_site, page_name):
    path = built_site / page_name
    page = Page(path.read_text(encoding='utf-8'))
    assert any(link and link.endswith('impressum.html') for link in page.links())
    assert any(link and link.endswith('privacy.html') for link in page.links())
    for tag, attrs in page.tags:
        resource = attrs.get('src')
        if tag == 'link' and attrs.get('rel') == 'stylesheet':
            resource = attrs.get('href')
        if resource:
            assert not resource.startswith(('http:', 'https:', '//', 'data:')), resource
            assert (path.parent / resource).is_file(), resource
        if tag == 'a':
            link = attrs.get('href', '')
            if link and not link.startswith(('https:', 'mailto:', '#')):
                target = path.parent / link.split('#')[0]
                assert target.exists(), link
    assert any(attrs.get('name') == 'referrer' and attrs.get('content') == 'no-referrer'
               for tag, attrs in page.tags if tag == 'meta')


def test_packaged_graph_uses_local_vendor_and_restricts_network_access(built_site):
    graph = (built_site / 'code-graph/index.html').read_text(encoding='utf-8')
    assert 'https://unpkg.com/' not in graph
    assert '../vendor/vis-network-9.1.6/vis-network.min.js' in graph
    assert "connect-src 'none'" in graph
    assert "'sha256-" in graph


def test_packager_rejects_unexpected_graph_runtime(built_site, tmp_path):
    graph = tmp_path / 'bad-graph.html'
    graph.write_text('<html><head><script src="https://other.example/script.js"></script></head><body></body></html>', encoding='utf-8')
    with pytest.raises(ValueError, match='vis-network'):
        packager().prepare_pages(ROOT, graph, tmp_path / 'rejected')


def test_packaged_vendor_bytes_match_graph_integrity_on_windows(built_site):
    graph = Page((built_site / 'code-graph/index.html').read_text(encoding='utf-8'))
    script = next(attrs for tag, attrs in graph.tags if tag == 'script' and attrs.get('integrity'))
    runtime = (built_site / 'code-graph' / script['src']).read_bytes()
    digest = base64.b64encode(hashlib.sha384(runtime).digest()).decode('ascii')
    assert script['integrity'] == 'sha384-' + digest


def test_graph_script_hash_uses_html_parser_end_tag_rules(tmp_path):
    body = 'window.graphReady = true;'
    graph = tmp_path / 'graph.html'
    graph.write_text('''<html><head>
<script src="https://unpkg.com/vis-network@9.1.6/standalone/umd/vis-network.min.js"></script>
</head><body><script>''' + body + '</script\t\n bar></body></html>', encoding='utf-8')
    output = tmp_path / 'public'
    packager().prepare_pages(ROOT, graph, output)
    html = (output / 'code-graph/index.html').read_text(encoding='utf-8')
    digest = base64.b64encode(hashlib.sha256(body.encode()).digest()).decode('ascii')
    assert "'sha256-" + digest + "'" in html


def test_packaged_graph_preserves_select_all_and_mobile_style_override(built_site):
    graph = (built_site / 'code-graph/index.html').read_text(encoding='utf-8')
    assert 'onchange=' not in graph
    assert '<script src="../graph.js" defer></script>' in graph
    assert graph.index('../graph.css') > graph.index('</style>')
    assert 'toggleAllCommunities' in (built_site / 'graph.js').read_text(encoding='utf-8')


def test_public_site_avoids_tracking_and_browser_storage():
    for path in (ROOT / 'site').glob('*.js'):
        text = path.read_text(encoding='utf-8')
        for forbidden in ('localStorage', 'sessionStorage', 'document.cookie', 'sendBeacon', 'fetch('):
            assert forbidden not in text


def test_local_quickstart_binds_only_loopback():
    text = LANDING_PAGE.read_text(encoding='utf-8')
    assert '-p 127.0.0.1:5000:5000' in text
    assert '-e CORS_ORIGINS=http://localhost:5000' in text
    assert 'mailto:hi@getwebssh.com' in text


def test_privacy_notice_distinguishes_hosting_from_self_hosted_product():
    text = (ROOT / 'site/privacy.html').read_text(encoding='utf-8')
    for required in ('GitHub Pages', 'IP address', 'Infomaniak', 'Article 6', 'Article 21', 'supervisory authority', 'independently hosted WebSSH instances'):
        assert required in text
    assert 'Google Analytics' not in text


def test_all_product_pages_are_english_and_have_one_main_heading(built_site):
    for filename in packager().PUBLIC_PAGES:
        text = (built_site / filename).read_text(encoding='utf-8')
        page = Page(text)
        assert ('html', {'lang': 'en'}) in page.tags
        assert sum(tag == 'h1' for tag, _ in page.tags) == 1
        for german in ('Datenschutz', '>Impressum<', 'Zum Inhalt', 'lang="de"'):
            assert german not in text


def test_search_metadata_matches_canonical_content_and_csp(built_site):
    module = packager()
    for filename in module.PUBLIC_PAGES:
        text = (built_site / filename).read_text(encoding='utf-8')
        metadata = module.SearchMetadata(text)
        page = Page(text)
        meta = {attrs.get('property', attrs.get('name')): attrs.get('content')
                for tag, attrs in page.tags if tag == 'meta'}
        assert meta['og:title'] == meta['twitter:title'] == metadata.titles[0]
        assert meta['og:description'] == meta['twitter:description'] == metadata.descriptions[0]
        assert meta['og:url'] == metadata.canonicals[0]
        assert meta['og:image'] == meta['twitter:image']
        assert (built_site / urlsplit(meta['og:image']).path.lstrip('/')).is_file()
        assert meta['robots'] == 'index, follow, max-image-preview:large'
        assets = module.RuntimeAssets()
        assets.feed(text)
        assets.close()
        assert len(assets.inline_scripts) == 1
        body = assets.inline_scripts[0]
        schema = json.loads(body)
        assert schema['@context'] == 'https://schema.org'
        webpage = next(node for node in schema['@graph'] if node['@type'] == 'WebPage')
        assert webpage['name'] == metadata.titles[0]
        assert webpage['description'] == metadata.descriptions[0]
        assert webpage['url'] == metadata.canonicals[0]
        assert webpage['inLanguage'] == 'en'
        digest = base64.b64encode(hashlib.sha256(body.encode()).digest()).decode('ascii')
        assert "'sha256-" + digest + "'" in metadata.policies[0]
        assert 'unsafe-inline' not in metadata.policies[0]
        assert "connect-src 'none'" in metadata.policies[0]
        if filename != 'index.html':
            breadcrumb = next(node for node in schema['@graph'] if node['@type'] == 'BreadcrumbList')
            assert [item['item'] for item in breadcrumb['itemListElement']] == [module.SITE_URL, webpage['url']]
        else:
            software = next(node for node in schema['@graph'] if node['@type'] == 'SoftwareSourceCode')
            assert software['codeRepository'] == 'https://github.com/bifrost0x/webssh'
            assert software['license'].endswith('/LICENSE')
            assert 'aggregateRating' not in body and 'ratingValue' not in body


def test_sitemap_and_robots_include_only_canonical_authored_pages(built_site):
    module = packager()
    sitemap = ElementTree.parse(built_site / 'sitemap.xml')
    urls = [element.text for element in sitemap.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}loc')]
    assert set(urls) == {module.SITE_URL + ('' if name == 'index.html' else name) for name in module.PUBLIC_PAGES}
    assert len(urls) == len(set(urls))
    robots = (built_site / 'robots.txt').read_text(encoding='utf-8')
    assert 'Sitemap: https://getwebssh.com/sitemap.xml' in robots
    assert 'User-agent: *\nAllow: /' in robots
    assert 'Disallow:' not in robots
    graph = Page((built_site / 'code-graph/index.html').read_text(encoding='utf-8'))
    assert any(attrs.get('name') == 'robots' and attrs.get('content') == 'noindex, follow'
               for tag, attrs in graph.tags if tag == 'meta')


def test_internal_links_and_fragments_resolve_and_doc_links_exist(built_site):
    for filename in packager().PUBLIC_PAGES:
        path = built_site / filename
        for href in Page(path.read_text(encoding='utf-8')).links():
            parts = urlsplit(href)
            if href.startswith('https://github.com/bifrost0x/webssh/blob/main/'):
                source = href.split('/blob/main/', 1)[1].split('#')[0]
                assert (ROOT / unquote(source)).is_file(), href
            if parts.scheme or parts.netloc:
                continue
            target = path.parent / unquote(parts.path) if parts.path else path
            if target.is_dir():
                target /= 'index.html'
            assert target.is_file(), (filename, href)
            if parts.fragment and target.suffix == '.html':
                ids = {attrs.get('id') for _, attrs in Page(target.read_text(encoding='utf-8')).tags}
                assert unquote(parts.fragment) in ids, (filename, href)


@pytest.mark.parametrize('replacement', [
    ('https://getwebssh.com/features.html', 'https://example.org/features.html'),
    ('<title>', '<title></title><title>'),
    ("script-src 'self';", "script-src 'self' 'unsafe-inline';"),
])
def test_metadata_build_rejects_drifted_page_contracts(tmp_path, replacement):
    output = tmp_path / 'site'
    shutil.copytree(ROOT / 'site', output)
    page = output / 'features.html'
    page.write_text(page.read_text(encoding='utf-8').replace(*replacement), encoding='utf-8')
    with pytest.raises(ValueError, match='metadata|policy'):
        packager().add_search_metadata(output)
