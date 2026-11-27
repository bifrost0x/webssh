"""Record the prompt state rules of the Python release (input_idle).

Usage (from the repository root, with the project virtual environment):

    .venv/bin/python -I internal/terminal/testdata/prompt_oracle.py . \
        > internal/terminal/testdata/prompt_oracle.json

The patterns and _note_prompt_output, _note_prompt_input and
prompt_input_idle are taken from app/ssh_manager.py by name and run
unchanged on sequences of output and input chunks.
"""

import ast
import base64
import json
import pathlib
import random
import re
import sys

root = pathlib.Path(sys.argv[1]).resolve()
source = (root / "app" / "ssh_manager.py").read_text()
tree = ast.parse(source)
wanted = {"_PROMPT_MODE", "_PROMPT_MODE_PREFIX", "_TERMINAL_REPLIES",
          "_note_prompt_output", "_note_prompt_input", "prompt_input_idle"}
nodes = []
for node in tree.body:
    names = set()
    if isinstance(node, ast.Assign):
        names = {t.id for t in node.targets if isinstance(t, ast.Name)}
    elif isinstance(node, ast.FunctionDef):
        names = {node.name}
    if names & wanted:
        nodes.append(node)
        wanted -= names
if wanted:
    raise SystemExit(f"missing in ssh_manager.py: {sorted(wanted)}")
scope = {"re": re}
exec(compile(ast.Module(body=nodes, type_ignores=[]), "ssh_manager.py", "exec"), scope)

PIECES_OUT = ["$ ", "\x1b[?2004h", "\x1b[?2004l", "\x1b[?1049h", "\x1b[?1049l", "\x1b[?1047h",
              "\x1b[?47l", "\x1b[?47h", "\x1b", "\x1b[", "\x1b[?", "\x1b[?20", "\x1b[?200", "04h", "4l",
              "049h", "ls\r\n", "grüße ", "\x1b[0m", "\x1b[?25h", "\x1b[?2004", "h"]
PIECES_IN = [b"l", b"s", b"\r", b"\x1b[?1;2c", b"\x1b[>0;276;0c", b"\x1b]11;rgb:0000/0000/0000\x07",
             b"\x1b]10;rgb:ffff/ffff/ffff\x1b\\", b"\x1b[?6C", b"\xff", b"\xc3", b"\x1b[A", b"",
             b"\x1b]12;rgb:1/2/3\x07", "ü".encode()]

rng = random.Random(7)
cases = []
for n in range(400):
    session = {}
    steps = []
    for _ in range(rng.randint(1, 12)):
        if rng.random() < 0.6:
            text = "".join(rng.choice(PIECES_OUT) for _ in range(rng.randint(1, 4)))
            scope["_note_prompt_output"](session, text)
            steps.append({"out": base64.b64encode(text.encode()).decode(), "idle": scope["prompt_input_idle"](session)})
        else:
            data = b"".join(rng.choice(PIECES_IN) for _ in range(rng.randint(1, 3)))
            scope["_note_prompt_input"](session, data)
            steps.append({"in": base64.b64encode(data).decode(), "idle": scope["prompt_input_idle"](session)})
    cases.append(steps)
json.dump(cases, sys.stdout, indent=None, separators=(",", ":"))
sys.stdout.write("\n")
