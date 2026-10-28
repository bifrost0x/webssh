"""Regression tests for distributable license notices and project metadata."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'license_consistency', ROOT / 'scripts/check_license_consistency.py',
)
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class LicenseConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        names = [*CHECK.FILES, 'LICENSE', 'LICENSE-MIT-ORIGINAL', 'NOTICE',
                 'package.json', 'package-lock.json']
        for name in dict.fromkeys(names):
            source = ROOT / name
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)

    def run_check(self):
        with patch.object(CHECK, 'ROOT', self.root), contextlib.redirect_stdout(io.StringIO()):
            CHECK.main()

    def test_current_distribution_is_consistent(self):
        self.run_check()

    def test_missing_legal_file_reports_failure_without_traceback(self):
        for name in ('LICENSE', 'LICENSE-MIT-ORIGINAL', 'NOTICE'):
            with self.subTest(name=name):
                source = (self.root / name).read_bytes()
                (self.root / name).unlink()
                try:
                    with self.assertRaisesRegex(SystemExit, name):
                        self.run_check()
                finally:
                    (self.root / name).write_bytes(source)

    def test_truncated_mit_permission_notice_is_rejected(self):
        (self.root / 'LICENSE-MIT-ORIGINAL').write_text(
            'MIT License\nCopyright (c) 2026 H31mdall\n', encoding='utf-8',
        )
        with self.assertRaisesRegex(SystemExit, 'LICENSE-MIT-ORIGINAL'):
            self.run_check()

    def test_truncated_apache_terms_are_rejected(self):
        (self.root / 'LICENSE').write_text(
            'Apache License\nVersion 2.0, January 2004\n', encoding='utf-8',
        )
        with self.assertRaisesRegex(SystemExit, 'LICENSE'):
            self.run_check()

    def test_empty_notice_is_rejected(self):
        (self.root / 'NOTICE').write_text('', encoding='utf-8')
        with self.assertRaisesRegex(SystemExit, 'NOTICE'):
            self.run_check()

    def test_stale_manifest_or_lock_license_is_rejected(self):
        for name in ('package.json', 'package-lock.json'):
            with self.subTest(name=name):
                original = (self.root / name).read_text(encoding='utf-8')
                value = json.loads(original)
                target = value if name == 'package.json' else value['packages']['']
                target['license'] = 'MIT'
                (self.root / name).write_text(json.dumps(value), encoding='utf-8')
                try:
                    with self.assertRaisesRegex(SystemExit, name):
                        self.run_check()
                finally:
                    (self.root / name).write_text(original, encoding='utf-8')

    def test_historical_and_vendor_mit_declarations_are_allowed(self):
        vendor = self.root / 'static/vendor/example/LICENSE'
        vendor.parent.mkdir(parents=True)
        vendor.write_text('MIT License', encoding='utf-8')
        self.run_check()


if __name__ == '__main__':
    unittest.main()
