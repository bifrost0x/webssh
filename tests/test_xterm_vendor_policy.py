"""Security invariants applied to deterministic vendored xterm output."""

from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_xterm_control_string_parser_limit_is_reduced_deterministically():
    vendor_script = (ROOT / 'scripts' / 'vendor.js').read_text(encoding='utf-8')
    vendored_xterm = (
        ROOT / 'static' / 'vendor' / 'xterm' / 'xterm.js'
    ).read_text(encoding='utf-8')

    assert "const parserLimit = 't.PAYLOAD_LIMIT=1e7'" in vendor_script
    assert "const boundedParserLimit = 't.PAYLOAD_LIMIT=2e5'" in vendor_script
    assert vendored_xterm.count('t.PAYLOAD_LIMIT=2e5') == 1
    assert 't.PAYLOAD_LIMIT=1e7' not in vendored_xterm
