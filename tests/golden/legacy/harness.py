"""Start the 3.3.x application on a legacy DATA_DIR for the pytest checks."""

import base64
import contextlib
import json
import shutil
from pathlib import Path

import pytest

from .. import runtime
from ..packing import extract_data_dir

ROOT = runtime.FIXTURE_ROOT / 'legacy'
MANIFEST = json.loads((ROOT / 'manifest.json').read_text(encoding='utf-8'))
MAIN = json.loads((runtime.FIXTURE_ROOT / 'manifest.json').read_text(encoding='utf-8'))
EXTENDED = MANIFEST['values']['extended']
PASSWORDS = MANIFEST['values']['passwords']


def release_values(archive):
    return MANIFEST['datadirs'][archive]['values']


def decode(value):
    return base64.b64decode(value)


def extract(archive, work):
    return extract_data_dir(ROOT / archive, work)


def apply_overlay(data_dir, variant):
    for name, content in variant.get('files', {}).items():
        path = Path(data_dir).parent / name
        if content is None:
            path.unlink()
        else:
            path.write_bytes(decode(content))


@contextlib.contextmanager
def started(data_dir, work, overrides=None):
    """The real Flask app on ``data_dir``; config is restored afterwards."""
    environment = runtime.environment(data_dir, work)
    environment.update(overrides or {})
    with pytest.MonkeyPatch.context() as patch:
        for name, value in environment.items():
            if name != 'TZ':
                patch.setenv(name, value)
        config = runtime.reload_config()
        from app import app_settings
        patch.setattr(app_settings, '_SETTINGS_FILE', config.DATA_DIR / 'app_settings.json')
        application = runtime.create_application()
        application.config['TESTING'] = True
        try:
            with application.app_context():
                yield application
        finally:
            runtime.shutdown(application)
    runtime.reload_config()


def copy_tree(source, destination):
    shutil.copytree(source, destination, symlinks=True)
    return destination
