"""Write shlex_vectors.json: random automation step commands and the exec
line of command_for in app/automation_transport.py for a sudo step.

Run from the repository root:
    .venv/bin/python internal/ssh/remotecmd/testdata/shlex_oracle.py
"""
import json
import random
import shlex
import sys

ALPHABET = (
    "abcXYZ019 _-./:,=+@%"  # the characters shlex.quote leaves alone
    "'\"`$\\!*?[]{}()<>|&;#~^\t\n"
    "äß日☃\U0001f600"
)


def command_for(command):
    # app/automation_transport.py command_for with step['sudo'] true
    return 'sudo -n -- sh -c ' + shlex.quote(command)


def main():
    rng = random.Random(20261127)
    cases = []
    for _ in range(1000):
        n = rng.randint(1, 40)
        c = ''.join(rng.choice(ALPHABET) for _ in range(n))
        cases.append({'c': c, 'l': command_for(c)})
    for c in ['a', "'", "''", 'safe-word_1.2:3,4=5+6@7%8/9', ' ', '\n', 'x' * 8192]:
        cases.append({'c': c, 'l': command_for(c)})
    out = 'internal/ssh/remotecmd/testdata/shlex_vectors.json'
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(cases, f, ensure_ascii=False, indent=0)
        f.write('\n')
    sys.stdout.write('%d vectors\n' % len(cases))


if __name__ == '__main__':
    main()
