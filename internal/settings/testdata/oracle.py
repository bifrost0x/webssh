"""Record how the Python release validates and encodes account settings.

Writes a corpus with the expected results so the Go tests replay it without
Python. Run from the repository root with the project virtual environment:

    WS=$PWD .venv/bin/python -I internal/settings/testdata/oracle.py \
        internal/settings/testdata/oracle.json
"""
import json
import os
import sys
import tempfile
from pathlib import Path

WS = Path(os.environ['WS'])
sys.path.insert(0, str(WS))
os.environ.setdefault('SECRET_KEY', '0' * 64)
os.environ['DATA_DIR'] = tempfile.mkdtemp(prefix='settings-oracle-')

from flask import Flask, render_template_string  # noqa: E402

from app.terminal_appearance import valid_terminal_appearance  # noqa: E402
from app.user_settings import (  # noqa: E402
    _known_overview_dismissed, _known_overview_panels, _valid_settings,
    _valid_settings_update, valid_overview_dismissed, valid_overview_layout,
)

APPEARANCE = [
    '{}', '[]', 'null', '"x"',
    '{"background": "#00ff00"}', '{"background": "#00FF0"}', '{"background": null}',
    '{"background": "#00ff00 "}', '{"foreground": "#abcdef"}', '{"cursor_color": "#ABCDEF"}',
    '{"selection_background": "red"}', '{"selection_background": 1}',
    '{"font_family": "Fira Code"}', '{"font_family": null}', '{"font_family": ""}',
    '{"font_family": "Fira;Code"}', '{"font_family": "' + 'a' * 64 + '"}',
    '{"font_family": "' + 'a' * 65 + '"}', '{"font_family": "Fira\\nCode"}',
    '{"font_family": "Fïra"}',
    '{"font_size": 8}', '{"font_size": 32}', '{"font_size": 7}', '{"font_size": 33}',
    '{"font_size": null}', '{"font_size": 12.0}', '{"font_size": true}', '{"font_size": "12"}',
    '{"line_height": 1}', '{"line_height": 2}', '{"line_height": 1.5}', '{"line_height": 0.99}',
    '{"line_height": 2.01}', '{"line_height": true}', '{"line_height": null}', '{"line_height": 1e0}',
    '{"line_height": 1e400}', '{"letter_spacing": -1}', '{"letter_spacing": 3}', '{"letter_spacing": -1.5}',
    '{"letter_spacing": 3.0}', '{"letter_spacing": false}',
    '{"font_weight": "normal"}', '{"font_weight": "bold"}', '{"font_weight": "bolder"}',
    '{"font_weight": null}',
    '{"background_opacity": 0}', '{"background_opacity": 100}', '{"background_opacity": 101}',
    '{"background_opacity": 50.0}', '{"background_opacity": -1}', '{"background_opacity": false}',
    '{"cursor_style": "block"}', '{"cursor_style": "underline"}', '{"cursor_style": "bar"}',
    '{"cursor_style": "beam"}', '{"cursor_blink": true}', '{"cursor_blink": 1}', '{"cursor_blink": null}',
    '{"unknown": 1}', '{"font_size": 14, "cursor_blink": false, "line_height": 1.2}',
]

PANELS = [
    'null', '[]', '{}', '"x"', '[null]', '[{}]',
    '[{"id": "hosts", "w": 4}]', '[{"id": "hosts", "w": 4, "h": null}]',
    '[{"id": "hosts", "w": 4, "h": 8}]', '[{"id": "hosts", "w": 4, "h": 160}]',
    '[{"id": "hosts", "w": 4, "h": 7}]', '[{"id": "hosts", "w": 4, "h": 161}]',
    '[{"id": "hosts", "w": 3}]', '[{"id": "hosts", "w": 12}]', '[{"id": "hosts", "w": 2}]',
    '[{"id": "hosts", "w": 13}]', '[{"id": "hosts", "w": 4.0}]', '[{"id": "hosts", "w": true}]',
    '[{"id": "hosts"}]', '[{"w": 4}]', '[{"id": "nope", "w": 4}]', '[{"id": 1, "w": 4}]',
    '[{"id": "hosts", "w": 4, "hidden": true}]', '[{"id": "hosts", "w": 4, "hidden": null}]',
    '[{"id": "hosts", "w": 4, "hidden": 0}]', '[{"id": "hosts", "w": 4, "extra": 1}]',
    '[{"id": "hosts", "w": 4}, {"id": "hosts", "w": 5}]',
    '[{"id": "hosts", "w": 4}, {"id": "kpis", "w": 6, "h": null, "hidden": false}]',
    json.dumps([{"id": p, "w": 4} for p in ('kpis', 'topology', 'hosts', 'attention', 'automation',
                                             'platforms', 'activity', 'continue', 'agents')]),
    json.dumps([{"id": p, "w": 4} for p in ('kpis', 'topology', 'hosts', 'attention', 'automation',
                                             'platforms', 'activity', 'continue', 'agents', 'kpis')]),
    '[{"id": "hosts", "w": 4}, {"id": "future", "w": 4}, {"id": "kpis", "w": 99}, {"id": "hosts", "w": 6}]',
]

DISMISSED = [
    '[]', 'null', '{}', '"x"', '[1]', '["host-keys:abc"]', '["host-keys:"]', '["host-keys"]',
    '[":abc"]', '["nope:abc"]', '["host-keys:a-b_c.d"]', '["host-keys:a b"]', '["host-keys:a:b"]',
    '["host-keys:äö"]', '["host-keys:٣"]', '["host-keys:abc", "host-keys:abc"]',
    '["unreachable:' + 'a' * 148 + '"]', '["unreachable:' + 'a' * 149 + '"]',
    '["reboot:x", "security-updates:y", "run-failed:z", "schedule-review:w", "credentials:v", '
    '"jump-missing:u", "socks-missing:t"]',
    json.dumps(['host-keys:%d' % i for i in range(100)]),
    json.dumps(['host-keys:%d' % i for i in range(101)]),
    '["host-keys:a", 5, "nope:b", "host-keys:a", "reboot:c"]',
]

# Settings files as Python stores them (schema 2); the Go import validates
# a whole document the same way.
FILES = [
    '{"schema_version": 2}', '{}', '{"schema_version": 1}', '[]',
    '{"schema_version": 2, "theme": "removed-theme"}', '{"schema_version": 2, "theme": 1}',
    '{"schema_version": 2, "start_page": "files"}', '{"schema_version": 2, "overview_layout": "grid"}',
    '{"schema_version": 2, "overview_reachability": "always"}',
    '{"schema_version": 2, "overview_panels": {}}', '{"schema_version": 2, "overview_panels": [1, 2]}',
    '{"schema_version": 2, "overview_dismissed": null}', '{"schema_version": 2, "overview_dismissed": [5]}',
    '{"schema_version": 2, "notepad": 5}', '{"schema_version": 2, "sync_terminal_directory": 1}',
    '{"schema_version": 2, "terminal_appearance": {"x": 1}}',
    '{"schema_version": 2, "confirm_session_close": "yes"}',
    '{"schema_version": 2, "disconnect_session_action": "reconnect"}',
    '{"schema_version": 2, "authentication_session_duration_minutes": 45}',
    '{"schema_version": 2, "authentication_session_duration_minutes": 60}',
    '{"schema_version": 2, "authentication_session_duration_minutes": 60.0}',
    '{"schema_version": 2, "intro_tour": {"any": "thing"}, "future_key": [1, 2]}',
    '{"schema_version": 2, "recovery_reviewed_at": ""}',
]


def parse(text):
    return json.loads(text)


def main(out):
    app = Flask('oracle')
    cases = {
        'appearance': [{'in': t, 'ok': valid_terminal_appearance(parse(t))} for t in APPEARANCE],
        'panels': [{'in': t, 'ok': valid_overview_layout(parse(t)),
                    'known': json.dumps(_known_overview_panels(parse(t)), sort_keys=True)} for t in PANELS],
        'dismissed': [{'in': t, 'ok': valid_overview_dismissed(parse(t)),
                       'known': _known_overview_dismissed(parse(t))} for t in DISMISSED],
        'files': [{'in': t, 'ok': _valid_settings(parse(t))} for t in FILES],
        'updates': [{'in': t, 'ok': _valid_settings_update(parse(t))} for t in FILES[4:]],
    }
    encode = [
        '{"panels": null, "dismissed": []}',
        '{"panels": [{"w": 4, "id": "hosts", "h": null, "hidden": false}], "dismissed": ["host-keys:a"]}',
        '{"x": "<&\'>\\u00e9\\ud83d\\ude00\\u007f\\u0001\\"\\\\/\\b\\f\\n\\r\\t\\u2028"}',
        '[1.0, 1e-05, 1e16, 0.1, 123456789012345678.0, 1.5e300, -0.0, 2, -0, 1.20, 1E2, 0.0001, 1e-7, '
        '123456789012345678901234567890, 9007199254740993, 5e-324, 1.7976931348623157e308, 100.0, 1e15, 1e+16]',
        '{"b": {"z": [], "a": {}}, "a": true, "c": false, "\\u00e4": 1, "Z": null}',
        '{"font_size": 14, "line_height": 1.2, "background": "#AbCdEf"}',
    ]
    with app.app_context():
        cases['encode'] = [{'in': t, 'out': render_template_string('{{ v|tojson }}', v=parse(t))}
                           for t in encode]
    Path(out).write_text(json.dumps(cases, indent=1, ensure_ascii=False) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main(sys.argv[1])
