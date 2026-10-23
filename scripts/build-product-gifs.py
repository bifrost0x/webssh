"""Encode product tours from browser captures (requires the optional Pillow package).

Run after WEBSSH_CAPTURE_ASSETS=1 product-captures.spec.js. No app data or
network access is used. Each frame is a real capture; transitions only crossfade.
"""

import argparse
from pathlib import Path

from PIL import Image


ROOT = Path(__file__).resolve().parents[1]
SIZE = (1280, 720)


def encode(paths, destination):
    stills = []
    for path in paths:
        with Image.open(path) as image:
            if image.width * 9 != image.height * 16:
                raise ValueError(f"Capture must be 16:9: {path.name}")
            stills.append(image.convert('RGB').resize(SIZE, Image.Resampling.LANCZOS))
    frames, durations = [], []
    for index, still in enumerate(stills):
        frames.append(still)
        durations.append(2600)
        following = stills[(index + 1) % len(stills)]
        for step in range(1, 6):
            frames.append(Image.blend(still, following, step / 6))
            durations.append(60)
    palette_frames = [image.quantize(colors=128) for image in frames]
    palette_frames[0].save(
        destination, save_all=True, append_images=palette_frames[1:],
        duration=durations, loop=0, disposal=2, optimize=False,
    )
    print(f"{destination.name}: {len(frames)} frames, {sum(durations) / 1000:.1f}s")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture-root', type=Path, default=ROOT)
    args = parser.parse_args()
    root = args.capture_root.resolve()
    assets = root / 'assets'
    frames = root / '.test-run.tmp'
    tours = {
        'webssh-demo.gif': [assets / name for name in (
            'workspace-overview.png', 'multi-session.png', 'sftp-workspace.png',
            'commandlibrary.png', 'command-set-builder.png', 'security-center.png',
        )],
        'file-editing.gif': [
            frames / 'file-editing-frames' / '01-dual-pane-overview.png',
            frames / 'file-editing-frames' / '03-readme-preview.png',
            frames / 'file-editing-frames' / '04-content-edited.png',
            assets / 'file-edit-review.png',
            frames / 'file-editing-frames' / '05-saved-preview.png',
            frames / 'file-editing-frames' / '06-transfer-complete.png',
        ],
        'command-sets.gif': sorted((frames / 'command-sets-frames').glob('*.png')),
    }
    for name, sources in tours.items():
        if len(sources) != 6 or any(not source.is_file() for source in sources):
            raise ValueError(f"Missing captures for {name}; run product captures first")
    for name, sources in tours.items():
        encode(sources, assets / name)


if __name__ == '__main__':
    main()
