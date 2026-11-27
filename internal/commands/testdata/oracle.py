"""Record how the Python release resolves command sets.

Writes a corpus with the expected results so the Go tests replay it without
Python. Run from the repository root with the project virtual environment:

    WS=$PWD .venv/bin/python -I internal/commands/testdata/oracle.py \
        internal/commands/testdata/oracle.json

Three kinds of case: "chain" resolves a stored set without parameters
(_resolve_loaded_command_set, with and without the sudo option) against a
small command index; "params" resolves a parameterised set with values
(resolve_parameters); "sudo" is _prefix_commands_with_sudo alone.
"""
import json
import os
import random
import sys
import tempfile
from pathlib import Path

WS = Path(os.environ['WS'])
sys.path.insert(0, str(WS))
os.environ.setdefault('SECRET_KEY', '0' * 64)
os.environ['DATA_DIR'] = tempfile.mkdtemp(prefix='commands-oracle-')

from app.command_parameters import resolve_parameters, validate_parameter_set  # noqa: E402
from app.command_set_manager import (  # noqa: E402
    _prefix_commands_with_sudo,
    _resolve_loaded_command_set,
)

INDEX = {
    'lib-plain': {'id': 'lib-plain', 'command': 'uptime', 'parameters': ''},
    'lib-args': {'id': 'lib-args', 'command': 'ls', 'parameters': '-la /tmp'},
    'lib-comment': {'id': 'lib-comment', 'command': 'echo hi', 'parameters': '# trailing'},
    'lib-semi': {'id': 'lib-semi', 'command': 'echo a;', 'parameters': ''},
}

FRAGMENTS = [
    'echo hi', 'uptime', '# only a comment', '  # indented comment', 'ls -la', 'sudo id', 'sudo', 'sudoedit x',
    'sudo\tls', 'cd /tmp;', 'sleep 1 &', 'echo "a # b"', "echo 'x;'", 'echo \\# not', 'a && b', 'x | y',
    'echo a # c', 'echo a; # c', 'echo a & # c', '', '   ', '\t', 'printf "%s\\n" "ünïcødé"', 'echo ✓ 服务器',
    'for i in 1 2; do echo $i; done', 'echo "unterminated', "echo 'open", 'echo \\', '(cd x)', 'cat <<EOF',
    'echo a\x1cb', '\x1c', 'echo a #b', 'true;;', 'echo &&', '#!/bin/sh', 'echo a#b',
]


def random_step(rng):
    lines = [rng.choice(FRAGMENTS) for _ in range(rng.randint(1, 4))]
    sep = rng.choice(['\n', '\n', '\r\n', '\r'])
    return sep.join(lines) + rng.choice(['', '', '\n', '\n\n', ' '])


def chain_cases(rng):
    cases = []
    for fragment in FRAGMENTS:
        cases.append([{'type': 'inline', 'command': fragment}, {'type': 'inline', 'command': 'uptime'}])
    for _ in range(700):
        steps = []
        for _ in range(rng.randint(1, 4)):
            if rng.random() < 0.2:
                step = {'type': 'library', 'command_id': rng.choice(list(INDEX) + ['missing'])}
                if rng.random() < 0.3:
                    step['parameters_override'] = rng.choice([None, '', '-h', '# c', 'a\x00b'])
                steps.append(step)
            else:
                steps.append({'type': 'inline', 'command': random_step(rng)})
        if rng.random() < 0.02:
            steps.append({'type': 'argv', 'argv': ['ls']})
        cases.append(steps)
    cases.append([{'type': 'inline', 'command': 'x' * 4097}])
    cases.append([{'type': 'inline', 'command': 'x' * 2000}, {'type': 'inline', 'command': 'y' * 2000},
                  {'type': 'inline', 'command': 'z' * 200}])
    cases.append([])
    out = []
    for steps in cases:
        for sudo in (False, True):
            command_set = {'name': 'Golden ✓', 'steps': steps, 'use_sudo': sudo, 'parameters': []}
            resolved, error = _resolve_loaded_command_set(command_set, INDEX)
            out.append({'kind': 'chain', 'steps': steps, 'use_sudo': sudo, 'resolved': resolved, 'error': error})
    return out


ARGS = ['ls', '-la', '{{path}}', '{{name}}', "it's", '', 'a b', '$(id)', '`id`', '"q"', 'ünï', '-', '--x=1',
        '{{undeclared}}', 'x{{path}}', '{{path}}}', '{{ path }}', '@%+=:,./-', 'tab\there', '\x7f', 'a\u0085b']
PROGRAMS = ['ls', 'grep', 'sh', '/bin/bash', 'python3.11', 'PERL', 'env', '.', './run', 'my-tool', 'a b', '',
            'x' * 257, '{{path}}', 'ünï', 'busybox', 'sudo', 'kubectl']
VALUES = ['/tmp', '', "it's", 'a b', '$(id)', '; rm -rf /', 'ünïcødé ✓', '\n', 'x' * 1025, 'x' * 1024, '\x9f',
          '--force', '*', '~', '!', '\\']


def params_cases(rng):
    out = []
    for _ in range(1500):
        names = rng.sample(['path', 'name', 'mode', 'bad-name', '_x', '1x', 'path'], rng.randint(0, 3))
        parameters = [{'name': n} for n in names]
        if rng.random() < 0.05:
            parameters.append({'name': 'extra', 'default': 'x'})
        if rng.random() < 0.03:
            parameters.append('path')
        steps = []
        for _ in range(rng.randint(0, 3)):
            argv = [rng.choice(PROGRAMS)] + [rng.choice(ARGS) for _ in range(rng.randint(0, 4))]
            if rng.random() < 0.05:
                argv.append(7)
            step = {'type': rng.choice(['argv'] * 9 + ['inline']), 'argv': argv}
            steps.append(step)
        command_set = {'name': 'P', 'parameters': parameters, 'steps': steps, 'use_sudo': rng.random() < 0.2}
        if rng.random() < 0.05:
            values = ['not', 'a', 'dict']
        else:
            values = {n: rng.choice(VALUES) for n in set(names) if rng.random() < 0.95}
            if rng.random() < 0.05:
                values['surplus'] = 'x'
            if rng.random() < 0.03 and values:
                values[next(iter(values))] = 5
        use_sudo = rng.random() < 0.2
        validation = validate_parameter_set(command_set)
        resolved, error = resolve_parameters(command_set, values, use_sudo)
        out.append({'kind': 'params', 'set': command_set, 'values': values, 'use_sudo': use_sudo,
                    'validation': validation, 'resolved': resolved, 'error': error})
    return out


def sudo_cases(rng):
    out = []
    for fragment in FRAGMENTS:
        out.append({'kind': 'sudo', 'text': fragment, 'resolved': _prefix_commands_with_sudo(fragment)})
    for _ in range(300):
        text = '\n'.join(rng.choice(FRAGMENTS) for _ in range(rng.randint(1, 5)))
        out.append({'kind': 'sudo', 'text': text, 'resolved': _prefix_commands_with_sudo(text)})
    return out


def main():
    rng = random.Random(20261127)
    cases = chain_cases(rng) + params_cases(rng) + sudo_cases(rng)
    with open(sys.argv[1], 'w', encoding='utf-8') as handle:
        json.dump(cases, handle, ensure_ascii=False, separators=(",", ":"))
        handle.write('\n')


main()
