#!/usr/bin/env python3
"""Verify vendored fonts offline, or rebuild from hash-locked release archives.

Check: python scripts/vendor-terminal-fonts.py
Rebuild: python scripts/vendor-terminal-fonts.py --source-dir /path/to/archives
Rebuilding needs Google's woff2_compress on PATH. Downloads are deliberately
not performed by this script. Source URLs and hashes are in manifest.json.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / 'static/vendor/terminal-fonts'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path)
    args = parser.parse_args()
    manifest = json.loads((DEST / 'manifest.json').read_text())
    for font in manifest['fonts']:
        if args.source_dir:
            archive = args.source_dir / font['archive_url'].rsplit('/', 1)[-1]
            if digest(archive.read_bytes()) != font['archive_sha256']:
                raise ValueError(f'Archive mismatch: {archive}')
            with tarfile.open(archive) as source, tempfile.TemporaryDirectory() as directory:
                for item in font['files']:
                    data = source.extractfile(item['source']).read()
                    if digest(data) != item['source_sha256']:
                        raise ValueError(f'Source mismatch: {item["source"]}')
                    path = Path(directory) / item['source']
                    path.write_bytes(data)
                    subprocess.run(['woff2_compress', str(path)], check=True, capture_output=True)
                    encoded = path.with_suffix('.woff2').read_bytes()
                    if digest(encoded) != item['sha256']:
                        raise ValueError(f'Conversion differs: {item["file"]}')
                    (DEST / item['file']).write_bytes(encoded)
        for item in font['files']:
            data = (DEST / item['file']).read_bytes()
            if data[:4] != b'wOF2' or digest(data) != item['sha256']:
                raise ValueError(f'Font mismatch: {item["file"]}')
    print(f'Verified {len(manifest["fonts"])} terminal font families.')


if __name__ == '__main__':
    main()
