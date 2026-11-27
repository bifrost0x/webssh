"""Record the exec request of an automation step as the Python release
builds it (command_for of app/automation_transport.py, unchanged).

    WS=$PWD .venv/bin/python -I internal/automation/testdata/command_line.py \
        internal/automation/testdata/command_line.json
"""
import json
import os
import sys
import tempfile
from pathlib import Path

WS = Path(os.environ['WS'])
sys.path.insert(0, str(WS))
os.environ.setdefault('SECRET_KEY', '0' * 64)
os.environ['DATA_DIR'] = tempfile.mkdtemp(prefix='automation-command-line-')

import app.automation_transport as transport  # noqa: E402

COMMANDS = [
    'id -un',
    'echo hello',
    "echo 'single'",
    'echo "double $HOME"',
    "it's",
    "''",
    "'",
    'a',
    '-n',
    'safe_chars@%+=:,./-',
    'tab\there',
    'line one\nline two',
    'for i in {1..3}; do echo $i; done',
    '[[ -n "$BASH_VERSION" ]] && echo bash || echo other',
    'arr=(a b c); echo "${arr[1]}"',
    'echo $((1 + 2)) | cat; exit 3',
    'printf "%s\\n" "$(uname -s)" `date +%Y`',
    'cd /tmp && ls -la > /dev/null 2>&1 &',
    'echo ünïcødé ✓',
    'x=$\'\\x41\'; echo "$x"',
    'cat <<EOF\nheredoc $USER\nEOF',
    '  leading and trailing spaces  ',
    '\\backslash\\',
    'echo "$(printf \'%s\' "nested \'quotes\'")"',
    '\r\ncarriage',
    "'" * 50,
    'x' * 8192,
    "'" * 8192,
]


def main(out):
    cases = []
    for command in COMMANDS:
        for sudo in (False, True):
            cases.append({'command': command, 'sudo': sudo,
                          'line': transport.command_for({'command': command, 'sudo': sudo})})
    Path(out).write_text(json.dumps(cases, ensure_ascii=False, indent=1) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main(sys.argv[1])
