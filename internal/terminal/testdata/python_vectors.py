"""Record the post-connect, tmux and Herdr rules of the Python release.

Usage (from the repository root, with the project virtual environment):

    .venv/bin/python -I internal/terminal/testdata/python_vectors.py . \
        > internal/terminal/testdata/python_vectors.json

app/startup_commands.py, app/post_connect_manager.py and app/herdr.py are
loaded unchanged from the given checkout; only the command library, the
command sets and the storage lock are replaced by the fixed library below,
which the Go test serves through terminal.Commands. The tmux session
command is taken from app/ssh_manager.py by name, and the tmux name
scheme, which create_ssh_connection builds inline, is checked against the
source text before it is used.
"""

import ast
import contextlib
import importlib.util
import json
import pathlib
import random
import shlex
import sys
import types
import uuid

root = pathlib.Path(sys.argv[1]).resolve()

package = types.ModuleType("app")
package.__path__ = [str(root / "app")]
sys.modules["app"] = package

COMMANDS = [
    {"id": "c-plain", "command": "uptime", "parameters": ""},
    {"id": "c-params", "command": "ls", "parameters": "-la /tmp"},
    {"id": "c-unicode", "command": "echo", "parameters": "grüße 🚀"},
    {"id": "c-multiline", "command": "printf 'a\\r\\nb'", "parameters": ""},
    {"id": "c-long", "command": "x" * 4090, "parameters": "abcdef"},
    {"id": "c-nul", "command": "echo", "parameters": "a\x00b"},
]
SETS = {
    "s-ok": ("cd /srv && make", None),
    "s-crlf": ("one\r\ntwo\rthree", None),
    "s-param": (None, "Parameterized command sets require interactive launch after connecting"),
}

commands = types.ModuleType("app.command_manager")
commands.get_all_commands = lambda user_id: [dict(c) for c in COMMANDS]
commands._get_all_commands_with_lock_held = commands.get_all_commands
sys.modules["app.command_manager"] = commands
package.command_manager = commands


def resolve_set(user_id, set_id):
    if set_id not in SETS:
        return None, "Command set not found"
    text, error = SETS[set_id]
    if error:
        return None, error
    return startup.normalize_startup_commands(text)


sets = types.ModuleType("app.command_set_manager")
sets._resolve_command_set_with_coordinator_held = resolve_set
sys.modules["app.command_set_manager"] = sets
package.command_set_manager = sets

storage = types.ModuleType("app.storage_utils")
storage.storage_lock = lambda name: contextlib.nullcontext()
sys.modules["app.storage_utils"] = storage


def load(name):
    spec = importlib.util.spec_from_file_location(f"app.{name}", root / "app" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"app.{name}"] = module
    setattr(package, name, module)
    spec.loader.exec_module(module)
    return module


startup = load("startup_commands")
post_connect = load("post_connect_manager")
herdr = load("herdr")

rng = random.Random(20261127)

# --- normalization --------------------------------------------------------

TEXTS = [
    "", "ls", "ls\n", "a\r\nb", "a\rb", "a\r\r\nb\n\r", "\r\n\r\n", "grüße\n🚀",
    "x" * 4096, "x" * 4097, "ü" * 4096, "ü" * 4097, "🚀" * 4096, "a\x00b", "\x00",
    "line1\nline2\n\n", "tab\there", " sep", "x" * 4095 + "\r\n",
]
for _ in range(200):
    alphabet = "ab \r\n\t\x00ü🚀;|&"
    TEXTS.append("".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 40))))

normalize = []
for text in TEXTS:
    out, error = startup.normalize_startup_commands(text)
    entry = {"in": text, "out": out, "error": error or ""}
    if not error:
        entry["input"] = startup.to_terminal_input(out).rstrip("\r") + "\r"
    normalize.append(entry)

parameters = [{"in": text, "error": startup.validate_command_parameters(text) or ""} for text in TEXTS]

# --- resolution -----------------------------------------------------------

MEMBERS = ["startup_mode", "startup_commands", "command_id", "command_set_id", "parameters_override"]
VALUES = {
    "startup_mode": [None, "none", "free_text", "command", "command_set", "shell", "NONE"],
    "startup_commands": [None, "", "ls -la", "a\r\nb", "x" * 4097, "a\x00"],
    "command_id": [None, "", "c-plain", "c-params", "c-unicode", "c-multiline", "c-long", "c-nul", "c-missing"],
    "command_set_id": [None, "", "s-ok", "s-crlf", "s-param", "s-missing"],
    "parameters_override": [None, "", "-h", "x" * 4097, "b\x00", "--name 'ü'"],
}

payloads = [
    {}, {"startup_mode": "none"}, {"startup_commands": "ls"}, {"command_id": "c-params"},
    {"command_set_id": "s-ok"}, {"command_id": "c-plain", "command_set_id": "s-ok"},
    {"startup_mode": "command", "command_id": "c-params", "parameters_override": None},
    {"startup_mode": "command", "command_id": "c-params", "parameters_override": ""},
    {"startup_mode": "command", "command_id": "c-long"},
    {"startup_mode": "command", "command_id": "c-long", "parameters_override": ""},
    {"startup_mode": "free_text", "command_id": "c-plain"},
    {"startup_mode": "none", "command_id": "c-plain", "startup_commands": "ls"},
]
for _ in range(600):
    payload = {}
    for member in MEMBERS:
        if rng.random() < 0.45:
            value = rng.choice(VALUES[member])
            if value is not None or member == "parameters_override":
                payload[member] = value
    payloads.append(payload)

resolution = []
for payload in payloads:
    text, error = post_connect.resolve_configuration(1, dict(payload))
    resolution.append({"payload": payload, "text": text or "", "error": error or ""})

# --- tmux -----------------------------------------------------------------

source = (root / "app" / "ssh_manager.py").read_text(encoding="utf-8")
SCHEME = [
    "safe_host = host.replace('.', '_').replace(':', '_').replace('-', '_')",
    "safe_user = username.replace('.', '_').replace('-', '_')",
    'tmux_session_name = f"{config.TMUX_SESSION_PREFIX}_{safe_user}_{safe_host}_{port}_{unique_suffix}"',
    "unique_suffix = uuid.uuid4().hex[:8]",
    "'env LANG=C.UTF-8 LC_ALL=C.UTF-8 tmux -u'",
]
for line in SCHEME:
    if line not in source:
        raise SystemExit(f"ssh_manager.py no longer contains: {line}")

tree = ast.parse(source)
function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_tmux_session_command")
scope = {"shlex": shlex}
exec(compile(ast.Module(body=[function], type_ignores=[]), "ssh_manager.py", "exec"), scope)
session_command = scope["_tmux_session_command"]


def python_name(prefix, user, host, port, suffix):
    safe_host = host.replace('.', '_').replace(':', '_').replace('-', '_')
    safe_user = user.replace('.', '_').replace('-', '_')
    return f"{prefix}_{safe_user}_{safe_host}_{port}_{suffix}"


USER_CHARS = "abcXYZ019_-."
HOST_CHARS = "abcz09.-:"
names = []
for prefix in ["webssh", "team_1", "x" * 80]:
    for _ in range(60):
        user = "".join(rng.choice(USER_CHARS) for _ in range(rng.randrange(1, 33)))
        host = "".join(rng.choice(HOST_CHARS) for _ in range(rng.randrange(1, 60)))
        port = rng.randrange(1, 65536)
        suffix = uuid.UUID(int=rng.getrandbits(128)).hex[:8]
        names.append({"prefix": prefix, "user": user, "host": host, "port": port, "suffix": suffix,
                      "name": python_name(prefix, user, host, port, suffix)})
for host in ["192.168.1.10", "2001:db8::1", "srv-01.example.org", "fe80::1%eth0"]:
    names.append({"prefix": "webssh", "user": "deploy.bot", "host": host, "port": 22, "suffix": "0a1b2c3d",
                  "name": python_name("webssh", "deploy.bot", host, 22, "0a1b2c3d")})

commands_out = []
for name in ["webssh_u_h_22_0a0b0c0d", "x" * 190, "a_b"]:
    for program in ["tmux", "env LANG=C.UTF-8 LC_ALL=C.UTF-8 tmux -u"]:
        for reconnect in (False, True):
            commands_out.append({"program": program, "name": name, "reattach": reconnect,
                                 "line": session_command(program, name, reconnect=reconnect)})

print(json.dumps({
    "python": sys.version.split()[0],
    "normalize": normalize,
    "parameters": parameters,
    "commands": COMMANDS,
    "sets": {k: {"text": v[0] or "", "error": v[1] or ""} for k, v in SETS.items()},
    "resolution": resolution,
    "tmux_names": names,
    "tmux_commands": commands_out,
    "herdr": {"available": herdr.AVAILABLE_COMMAND, "session": herdr.SESSION_COMMAND},
}, ensure_ascii=False))
