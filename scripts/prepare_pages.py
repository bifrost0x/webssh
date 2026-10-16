"""Build the static product site and its locally served code graph."""

import argparse
import base64
import hashlib
from html.parser import HTMLParser
from pathlib import Path
import re
import shutil


GRAPH_CDN = 'https://unpkg.com/vis-network@9.1.6/standalone/umd/vis-network.min.js'
GRAPH_VENDOR = 'vendor/vis-network-9.1.6/vis-network.min.js'


class RuntimeAssets(HTMLParser):
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if any(name.startswith('on') for name in attrs):
            raise ValueError('Unexpected inline event handler in Graphify output')
        resource = attrs.get('src')
        if tag == 'link' and attrs.get('rel') in {'stylesheet', 'preload', 'modulepreload'}:
            resource = attrs.get('href')
        if resource and resource.startswith(('https:', 'http:', '//')):
            raise ValueError(f'External runtime asset remains: {resource}')


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
    RuntimeAssets().feed(graph_html)
    script_hashes = []
    for attrs, body in re.findall(r'<script\b([^>]*)>(.*?)</script\s*>', graph_html, re.I | re.S):
        if not re.search(r'\bsrc\s*=', attrs, re.I):
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
        f'<meta http-equiv="Content-Security-Policy" content="{policy}">\n'
    )
    # The policy must precede all scripts, including the vendored graph runtime.
    graph_html = graph_html.replace('<head>', '<head>\n' + metadata, 1)
    graph_html = graph_html.replace('</head>', '<link rel="stylesheet" href="../graph.css">\n</head>', 1)
    graph_html = graph_html.replace('</body>', '''<script src="../graph.js" defer></script>
<nav class="graph-site-nav" aria-label="Website and legal information">
<a href="../">WebSSH</a><a href="../impressum.html" lang="de">Impressum</a>
<a href="../privacy.html">Privacy / Datenschutz</a>
</nav></body>''', 1)
    # A fresh directory prevents files from an older build entering the artifact.
    output.mkdir(parents=True, exist_ok=False)
    shutil.copytree(root / 'site', output, dirs_exist_ok=True)
    # Preserve Graphify's upstream SRI hash even with a Windows CRLF checkout.
    runtime = output / GRAPH_VENDOR
    runtime.write_bytes(runtime.read_bytes().replace(b'\r\n', b'\n'))
    shutil.copytree(root / 'assets', output / 'assets', dirs_exist_ok=True)
    resources = {
        'static/images/webssh-logo.svg': 'webssh-logo.svg',
        'static/images/theme-backgrounds/carbon-glass.webp': 'carbon-glass.webp',
        'static/vendor/material-icons/material-icons.woff2': 'material-icons.woff2',
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
