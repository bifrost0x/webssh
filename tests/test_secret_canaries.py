"""Secret-scan canaries must stay detectable by the generic key rule."""

import importlib.util
import math
import re
from collections import Counter
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'check_repository_secrets.py'
_spec = importlib.util.spec_from_file_location('check_repository_secrets', _SCRIPT)
check_repository_secrets = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_repository_secrets)


def _entropy(value):
    counts = Counter(value)
    return -sum(count / len(value) * math.log2(count / len(value)) for count in counts.values())


def test_canary_values_cannot_spell_a_word_the_scanner_skips():
    for _ in range(200):
        value = check_repository_secrets.canary_value()
        assert len(value) == 64
        # No two letters touch, so no stop word such as "dead" or "add" can form.
        assert not re.search(r'[a-z]{2}', value)
        assert re.fullmatch(r'(?:[a-z][0-9])+', value)
        # The generic rule also needs a random-looking value.
        assert _entropy(value) > 3.5


def test_canary_values_differ_between_runs():
    assert len({check_repository_secrets.canary_value() for _ in range(50)}) == 50
