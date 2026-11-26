"""Record the decisions of the Python SSH gateway as test vectors.

Usage (from the repository root, with the project virtual environment):

    .venv/bin/python -I internal/ssh/gateway/testdata/python_vectors.py . \
        > internal/ssh/gateway/testdata/python_vectors.json

app/ssh_gateway.py, app/ssh_gateway_auth.py and
app/ssh_gateway_interaction.py are loaded unchanged from the given
checkout. Only collaborators are replaced: the quota manager, the admin
setting and the paramiko transport. The fake transport implements the
scripted servers of standin_test.go (the same modes), so the Go tests run
each scenario against an x/crypto server with the same behaviour.
"""

import importlib.util
import json
import pathlib
import random
import sys
import types

import paramiko

root = pathlib.Path(sys.argv[1]).resolve()

package = types.ModuleType("app")
package.__path__ = [str(root / "app")]
sys.modules["app"] = package

quota = types.ModuleType("app.quota_manager")
quota.QuotaKind = types.SimpleNamespace(BACKGROUND_JOB="background_job", SSH_SESSION="ssh_session")
quota.quota_manager = None
sys.modules["app.quota_manager"] = quota

settings = types.ModuleType("app.app_settings")
settings.is_ssh_gateway_enabled = lambda: True
sys.modules["app.app_settings"] = settings


def load(name):
    spec = importlib.util.spec_from_file_location(f"app.{name}", root / "app" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"app.{name}"] = module
    setattr(package, name, module)
    spec.loader.exec_module(module)
    return module


gateway = load("ssh_gateway")
auth = load("ssh_gateway_auth")
load("ssh_connection_attempt")
interaction = load("ssh_gateway_interaction")

# --- selectors and tmux names ---------------------------------------------

SELECTORS = [
    "alice:prod", "alice@example.com:production", "ticket-abc:x", "a#b:c", "nouser",
    ":t", "u:", " u:t", "u:t ", "u:\u00a0t", "u:\u200bt", "u:t\u2028", "ü:ziel", "u:" + "x" * 126,
    "u:" + "x" * 127, "a:b:c", "u:\x7f", "u:t\u202e", "u:\u3000t", "u:\t", "u\u2029:t", "u:t\ufeff",
    "ticket-", "tickets:x", "Ticket-abc:x", "u:#", "u :t", "u\u3000:t", "u:é" * 1, "u:" + "é" * 63,
    "u:" + "é" * 64, "😀:t", "u:t\u00ad", "u:\u0085", "user:\u2066t",
]


def selector_outcome(value):
    try:
        return {"in": value, "ok": True, "out": list(gateway.parse_selector(value))}
    except ValueError as error:
        return {"in": value, "ok": False, "error": str(error)}


rng = random.Random(20261127)
alphabet = ["a", "b", ":", " ", "#", "-", "t", "\u00a0", "\u200b", "é", "😀", "\u2028", "\x00", "\x1f", "\t", "i", "c", "k", "e"]
generated = []
for _ in range(400):
    generated.append("".join(rng.choice(alphabet) for _ in range(rng.randint(0, 12))))
for prefix in ("ticket-", " ", ""):
    generated.append(prefix + "x:y")

TMUX = [(1, "gw.lan", 22, "alice:prod"), ("7", "fd7a::1", 2222, "ü:ziel"),
        (42, "gw.lan", 22, 'q"u\\o:te\u2603\U0001F600'), (3, "Host\x01", 1, "a:\u00e9\u20ac")]
tmux = []
for user_id, host, port, selector in TMUX:
    for prefix in ("webssh", "wéb ssh-x", "x" * 90):
        name = gateway.tmux_name(prefix, host, port, selector, user_id)
        tmux.append({"user_id": int(user_id), "host": host, "port": port, "selector": selector,
                     "prefix": prefix, "name_without_uuid": name.rsplit("_", 1)[0]})

# --- authentication strategy ----------------------------------------------

OTP = "424242"
PASSWORD = "synthetic-password"
KEY = object()


class FakeTransport:
    """The servers of standin_test.go as paramiko sees them."""

    def __init__(self, mode):
        self.mode = mode
        self.used = []
        self.authenticated = False
        self.auth_timeout = None
        stage = {
            "otp": ["keyboard-interactive"],
            "password": ["password"],
            "key+otp": ["publickey"],
            "password+otp": ["password"],
            "ki-broken+password": ["keyboard-interactive", "password"],
            "ki+password": ["keyboard-interactive", "password"],
        }[mode]
        self.allowed = stage

    def is_authenticated(self):
        return self.authenticated

    def is_active(self):
        return True

    def close(self):
        pass

    def _refuse_type(self, method):
        if method not in self.allowed:
            raise paramiko.BadAuthenticationType("Bad authentication type", list(self.allowed))

    def _succeed(self, method):
        if (self.mode, method) in (("key+otp", "publickey"), ("password+otp", "password")):
            self.allowed = ["keyboard-interactive"]
            return list(self.allowed)
        self.authenticated = True
        return []

    def auth_none(self, username):
        raise paramiko.BadAuthenticationType("Bad authentication type", list(self.allowed))

    def auth_publickey(self, username, key):
        self._refuse_type("publickey")
        self.used.append("publickey")
        if key is not KEY:
            raise paramiko.AuthenticationException("denied")
        return self._succeed("publickey")

    def auth_password(self, username, password, fallback=True):
        self._refuse_type("password")
        self.used.append("password")
        if password != PASSWORD:
            raise paramiko.AuthenticationException("denied")
        return self._succeed("password")

    def auth_interactive(self, username, handler, submethods=""):
        self._refuse_type("keyboard-interactive")
        self.used.append("keyboard-interactive")
        if self.mode == "ki-broken+password":
            raise paramiko.AuthenticationException("no backend")
        answers = handler("Warpgate", "Enter the one-time code for " + username, [("OTP: ", False)])
        if list(answers) != [OTP]:
            raise paramiko.AuthenticationException("bad otp")
        return self._succeed("keyboard-interactive")


SCENARIOS = []
for mode in ["otp", "password", "key+otp", "password+otp", "ki-broken+password", "ki+password"]:
    for user in ["alice:prod", "pwuser"]:
        for password in ["", "*", "wrong"]:
            for key in [False, True]:
                for answer in [OTP, "000000"]:
                    SCENARIOS.append((mode, user, password, key, answer))

auth_vectors = []
for mode, user, password, key, answer in SCENARIOS:
    transport = FakeTransport(mode)
    prompts = []

    def interact(title, instructions, questions, answer=answer, prompts=prompts):
        prompts.append([label for label, _echo in questions])
        if len(questions) == 1 and questions[0][0] == "Password":
            return [PASSWORD]
        return [answer for _ in questions]

    saved = {"": None, "*": PASSWORD, "wrong": "wrong-password"}[password]
    strategy = auth.GatewayAuthStrategy(user, password=saved, pkey=KEY if key else None, interact=interact)
    try:
        strategy.authenticate(transport)
        outcome = "ok" if transport.is_authenticated() else "failed"
    except paramiko.AuthenticationException:
        outcome = "failed"
    auth_vectors.append({"mode": mode, "user": user, "password": password, "key": key, "answer": answer,
                         "outcome": outcome, "used": transport.used, "prompts": prompts})

# --- interaction rules ------------------------------------------------------


def attempt():
    a = interaction.GatewayAttempt(7, "sid-1", "req", lambda event, payload: None, require_gateway=True)
    a.guard.cancel()
    return a


answer_cases = []
for prompts, answers, user, sid, same_id in [
    (1, ["1"], 7, "sid-1", True), (1, ["1"], 8, "sid-1", True), (1, ["1"], 7, "sid-2", True),
    (1, ["1"], 7, "sid-1", False), (2, ["1"], 7, "sid-1", True), (0, [], 7, "sid-1", True),
    (1, ["x" * 16384], 7, "sid-1", True), (1, ["x" * 16385], 7, "sid-1", True),
    (2, ["é" * 8192, ""], 7, "sid-1", True), (2, ["é" * 8192, "x"], 7, "sid-1", True),
    (8, [str(i) for i in range(8)], 7, "sid-1", True),
]:
    a = attempt()
    a.prompt = ("cid", prompts)
    first = a.answer(user, sid, "cid" if same_id else "other", answers)
    replay = a.answer(user, sid, "cid" if same_id else "other", answers) if first else None
    answer_cases.append({"prompts": prompts, "answers": answers, "other_user": user != 7,
                         "other_connection": sid != "sid-1", "same_id": same_id,
                         "ok": first, "replay_ok": replay})

input_cases = []
for phase, values in [
    ("auth", ["y"]),
    ("setup", ["y", "", "a" * 1024, "a" * 1025, "é" * 512, "é" * 513]),
    ("setup", ["a" * 1024] * 9),
    ("setup", ["a" * 1000] * 8 + ["a" * 192, "a"]),
]:
    a = attempt()
    a.phase = phase
    input_cases.append({"phase": phase, "values": values, "ok": [a.input(v) for v in values]})

ack_cases = []
a = attempt()
a.unacked = {1: True, 2: True}
for sequence in [1, 1, 3, 2, 0]:
    ack_cases.append({"sequence": sequence, "ok": a.ack(sequence)})

json.dump({
    "python": sys.version.split()[0],
    "paramiko": paramiko.__version__,
    "selectors": [selector_outcome(s) for s in SELECTORS + generated],
    "tmux": tmux,
    "auth": auth_vectors,
    "answers": answer_cases,
    "inputs": input_cases,
    "acks": ack_cases,
}, sys.stdout, ensure_ascii=False, indent=1)
sys.stdout.write("\n")
