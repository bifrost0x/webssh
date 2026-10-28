"""Build the static product site and its locally served code graph."""

import argparse
import base64
import hashlib
from html import escape
from html.parser import HTMLParser
import json
from pathlib import Path
import shutil


GRAPH_CDN = 'https://unpkg.com/vis-network@9.1.6/standalone/umd/vis-network.min.js'
GRAPH_VENDOR = 'vendor/vis-network-9.1.6/vis-network.min.js'
SITE_URL = 'https://getwebssh.com/'
PUBLIC_PAGES = {
    'index.html': 'Home',
    'features.html': 'Features',
    'demo.html': 'Demo',
    'self-hosting.html': 'Self-hosting',
    'security.html': 'Security',
    'impressum.html': 'Legal notice',
    'privacy.html': 'Privacy notice',
}


class SearchMetadata(HTMLParser):
    """Read the same title, description and canonical URL that visitors receive."""

    def __init__(self, text):
        super().__init__()
        self.titles = []
        self.descriptions = []
        self.canonicals = []
        self.policies = []
        self._title = None
        self.feed(text)
        self.close()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'title':
            self._title = []
        elif tag == 'meta' and attrs.get('name') == 'description':
            self.descriptions.append(attrs.get('content', ''))
        elif tag == 'meta' and attrs.get('http-equiv') == 'Content-Security-Policy':
            self.policies.append(attrs.get('content', ''))
        elif tag == 'link' and attrs.get('rel') == 'canonical':
            self.canonicals.append(attrs.get('href', ''))

    def handle_data(self, data):
        if self._title is not None:
            self._title.append(data)

    def handle_endtag(self, tag):
        if tag == 'title' and self._title is not None:
            self.titles.append(''.join(self._title))
            self._title = None


def add_search_metadata(output: Path) -> None:
    """Package consistent crawlable metadata without adding a browser dependency."""
    if {path.name for path in output.glob('*.html')} != set(PUBLIC_PAGES):
        raise ValueError('Authored pages and public page inventory differ')
    urls = []
    titles = set()
    descriptions = set()
    for filename, label in PUBLIC_PAGES.items():
        path = output / filename
        html = path.read_text(encoding='utf-8')
        metadata = SearchMetadata(html)
        url = SITE_URL + ('' if filename == 'index.html' else filename)
        if (len(metadata.titles) != 1 or not metadata.titles[0]
                or len(metadata.descriptions) != 1 or not metadata.descriptions[0]
                or metadata.canonicals != [url] or len(metadata.policies) != 1
                or html.count('</head>') != 1):
            raise ValueError(f'Invalid search metadata in {filename}')
        title, description = metadata.titles[0], metadata.descriptions[0]
        if title in titles or description in descriptions:
            raise ValueError(f'Duplicate search metadata in {filename}')
        titles.add(title)
        descriptions.add(description)
        urls.append(url)
        nodes = [{
            '@type': 'WebPage', '@id': url + '#webpage', 'url': url,
            'name': title, 'description': description, 'inLanguage': 'en',
            'isPartOf': {'@id': SITE_URL + '#website'},
            'about': {'@id': SITE_URL + '#software'},
        }]
        if filename == 'index.html':
            nodes.extend([
                {'@type': 'WebSite', '@id': SITE_URL + '#website', 'url': SITE_URL,
                 'name': 'WebSSH', 'inLanguage': 'en',
                 'publisher': {'@id': SITE_URL + '#maintainer'}},
                {'@type': 'SoftwareSourceCode', '@id': SITE_URL + '#software',
                 'name': 'WebSSH', 'url': SITE_URL, 'description': description,
                 'codeRepository': 'https://github.com/bifrost0x/webssh',
                 'license': 'https://github.com/bifrost0x/webssh/blob/main/LICENSE',
                 'programmingLanguage': ['Python', 'JavaScript'],
                 'runtimePlatform': 'Python 3.11+',
                 'author': {'@id': SITE_URL + '#maintainer'},
                 'image': SITE_URL + 'assets/session-workspace.png'},
                {'@type': 'Person', '@id': SITE_URL + '#maintainer',
                 'name': 'Marcel Graewer', 'url': SITE_URL + 'impressum.html'},
            ])
        else:
            nodes[0]['breadcrumb'] = {'@id': url + '#breadcrumb'}
            nodes.append({
                '@type': 'BreadcrumbList', '@id': url + '#breadcrumb',
                'itemListElement': [
                    {'@type': 'ListItem', 'position': 1, 'name': 'Home', 'item': SITE_URL},
                    {'@type': 'ListItem', 'position': 2, 'name': label, 'item': url},
                ],
            })
        if filename == 'demo.html':
            video_id = url + '#video'
            nodes[0]['mainEntity'] = {'@id': video_id}
            nodes.append({
                '@type': 'VideoObject', '@id': video_id,
                'name': 'WebSSH: Self-Hosted SSH & SFTP in Your Browser',
                'description': description,
                'thumbnailUrl': [SITE_URL + 'assets/webssh-youtube-tour.jpg'],
                'url': 'https://www.youtube.com/watch?v=mw_qXUnYYVs',
                'embedUrl': 'https://www.youtube-nocookie.com/embed/mw_qXUnYYVs',
                'uploadDate': '2026-10-18T13:27:58+02:00',
                'duration': 'PT4M33S', 'inLanguage': 'en',
                'width': 1920, 'height': 1080,
                'about': {'@id': SITE_URL + '#software'},
            })
        structured = json.dumps({'@context': 'https://schema.org', '@graph': nodes},
                                ensure_ascii=False, separators=(',', ':')).replace('<', '\\u003c')
        digest = base64.b64encode(hashlib.sha256(structured.encode('utf-8')).digest()).decode('ascii')
        policy = metadata.policies[0]
        if policy.count("script-src 'self';") != 1:
            raise ValueError(f'Unexpected authored page script policy in {filename}')
        html = html.replace(policy, policy.replace("script-src 'self';", f"script-src 'self' 'sha256-{digest}';"), 1)
        image = SITE_URL + 'assets/session-workspace.png'
        image_alt = 'WebSSH browser workspace with an SSH terminal and SFTP files side by side'
        if filename == 'demo.html':
            image = SITE_URL + 'assets/webssh-youtube-tour.jpg'
            image_alt = 'WebSSH product walkthrough with terminals, SFTP files and command sets'
        tags = {
            'og:type': 'website', 'og:site_name': 'WebSSH', 'og:locale': 'en_US',
            'og:title': title, 'og:description': description, 'og:url': url,
            'og:image': image, 'og:image:type': 'image/jpeg' if filename == 'demo.html' else 'image/png',
            'og:image:width': '1280' if filename == 'demo.html' else '2560',
            'og:image:height': '720' if filename == 'demo.html' else '1440', 'og:image:alt': image_alt,
        }
        social = ''.join(f'  <meta property="{key}" content="{escape(value, quote=True)}">\n'
                         for key, value in tags.items())
        twitter = {'twitter:card': 'summary_large_image', 'twitter:title': title,
                   'twitter:description': description, 'twitter:image': image,
                   'twitter:image:alt': image_alt}
        social += ''.join(f'  <meta name="{key}" content="{escape(value, quote=True)}">\n'
                          for key, value in twitter.items())
        social += '  <meta name="robots" content="index, follow, max-image-preview:large">\n'
        social += f'  <script type="application/ld+json">{structured}</script>\n'
        html = html.replace('</head>', social + '</head>', 1)
        path.write_text(html, encoding='utf-8', newline='\n')
    entries = ''.join(f'  <url><loc>{escape(url)}</loc></url>\n' for url in urls)
    (output / 'sitemap.xml').write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + entries + '</urlset>\n', encoding='utf-8', newline='\n')
    (output / 'robots.txt').write_text(
        'User-agent: *\nAllow: /\n\nSitemap: ' + SITE_URL + 'sitemap.xml\n',
        encoding='utf-8', newline='\n')


class RuntimeAssets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.inline_scripts = []
        self._script_parts = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if any(name.startswith('on') for name in attrs):
            raise ValueError('Unexpected inline event handler in Graphify output')
        resource = attrs.get('src')
        if tag == 'link' and attrs.get('rel') in {'stylesheet', 'preload', 'modulepreload'}:
            resource = attrs.get('href')
        if resource and resource.startswith(('https:', 'http:', '//')):
            raise ValueError(f'External runtime asset remains: {resource}')
        if tag == 'script' and 'src' not in attrs:
            self._script_parts = []

    def handle_data(self, data):
        if self._script_parts is not None:
            self._script_parts.append(data)

    def handle_endtag(self, tag):
        if tag == 'script' and self._script_parts is not None:
            self.inline_scripts.append(''.join(self._script_parts))
            self._script_parts = None

    def close(self):
        super().close()
        if self._script_parts is not None:
            raise ValueError('Unclosed inline script in Graphify output')


def prepare_pages(root: Path, graph_source: Path, output: Path) -> None:
    graph_html = graph_source.read_text(encoding='utf-8')
    if graph_html.count(GRAPH_CDN) != 1:
        raise ValueError('Graphify vis-network URL was missing or appeared more than once')
    if not (root / 'site' / GRAPH_VENDOR).is_file():
        raise ValueError('Missing vendored vis-network dependency')
    if graph_html.count('</head>') != 1 or graph_html.count('</body>') != 1:
        raise ValueError('Unexpected Graphify document structure')
    graph_html = graph_html.replace(GRAPH_CDN, '../' + GRAPH_VENDOR)
    graph_html = graph_html.replace(' onchange="toggleAllCommunities(!this.checked)"', '')
    assets = RuntimeAssets()
    assets.feed(graph_html)
    assets.close()
    script_hashes = []
    for body in assets.inline_scripts:
        digest = base64.b64encode(hashlib.sha256(body.encode('utf-8')).digest()).decode('ascii')
        script_hashes.append(f"'sha256-{digest}'")
    policy = (
        "default-src 'none'; script-src 'self' " + ' '.join(script_hashes)
        + "; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; "
        "connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"
    )
    metadata = (
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta name="referrer" content="no-referrer">\n'
        '<meta name="robots" content="noindex, follow">\n'
        f'<meta http-equiv="Content-Security-Policy" content="{policy}">\n'
    )
    # The policy must precede all scripts, including the vendored graph runtime.
    graph_html = graph_html.replace('<head>', '<head>\n' + metadata, 1)
    graph_html = graph_html.replace('</head>', '<link rel="stylesheet" href="../graph.css">\n</head>', 1)
    graph_html = graph_html.replace('</body>', '''<script src="../graph.js" defer></script>
<nav class="graph-site-nav" aria-label="Website and legal information">
<a href="../">WebSSH</a><a href="../impressum.html">Legal notice</a>
<a href="../privacy.html">Privacy notice</a>
</nav></body>''', 1)
    # A fresh directory prevents files from an older build entering the artifact.
    output.mkdir(parents=True, exist_ok=False)
    shutil.copytree(root / 'site', output, dirs_exist_ok=True)
    for name in ('LICENSE', 'THIRD-PARTY-NOTICES', 'NOTICE'):
        shutil.copyfile(root / name, output / name)
    add_search_metadata(output)
    # Preserve Graphify's upstream SRI hash even with a Windows CRLF checkout.
    runtime = output / GRAPH_VENDOR
    runtime.write_bytes(runtime.read_bytes().replace(b'\r\n', b'\n'))
    shutil.copytree(root / 'assets', output / 'assets', dirs_exist_ok=True)
    resources = {
        'static/images/webssh-logo.svg': 'webssh-logo.svg',
        'static/images/theme-backgrounds/carbon-glass.webp': 'carbon-glass.webp',
        'static/vendor/material-icons/material-icons.woff2': 'material-icons.woff2',
        'static/vendor/material-icons/LICENSE': 'material-icons-LICENSE',
    }
    for source, target in resources.items():
        shutil.copyfile(root / source, output / 'assets' / target)
    (output / 'code-graph').mkdir()
    (output / 'code-graph/index.html').write_text(graph_html, encoding='utf-8', newline='\n')
    (output / '.nojekyll').touch()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('_site'))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    prepare_pages(root, root / 'graphify-out/graph.html', args.output)
    print(f'Pages artifact prepared at {args.output}')


if __name__ == '__main__':
    main()
