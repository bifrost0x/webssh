"""Record the decisions of the Python Tailscale SSH policy as test vectors.

Usage (from the repository root, with the venv in $WEBSSH_PYTHON_ROOT):

    $WEBSSH_PYTHON_ROOT/.venv/bin/python -I internal/ssh/tailscale/testdata/python_vectors.py "$WEBSSH_PYTHON_ROOT" \
        > internal/ssh/tailscale/testdata/python_vectors.json

app/tailscale_ssh.py and app/network_policy.py are loaded unchanged from
the given checkout, parse_tailscale_ssh_target is lifted from config.py.
Only collaborators are replaced: the configuration, the resolver and the
kernel route lookup (a table per case). Every case runs the whole decision
of validate_tailscale_ssh_access, authorize_tailscale_ssh_access (the
pinned address), TailscaleSSHAuthorization.matches and
profile_is_authorized_for_launch.
"""

import ast
import importlib.util
import ipaddress
import itertools
import json
import pathlib
import random
import socket
import sys
import types

root = pathlib.Path(sys.argv[1]).resolve()

package = types.ModuleType("app")
package.__path__ = [str(root / "app")]
sys.modules["app"] = package

config = types.ModuleType("config")
tree = ast.parse((root / "config.py").read_text())
namespace = {"ipaddress": ipaddress}
for node in tree.body:
    if isinstance(node, ast.FunctionDef) and node.name in {"parse_tailscale_ssh_target", "_canonical_hostname"}:
        exec(compile(ast.Module([node], []), "config.py", "exec"), namespace)
sys.modules["config"] = config

audit = types.ModuleType("app.audit_logger")
audit.log_info = audit.log_warning = lambda *args, **kwargs: None
sys.modules["app.audit_logger"] = audit


def load(name):
    spec = importlib.util.spec_from_file_location(f"app.{name}", root / "app" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"app.{name}"] = module
    setattr(package, name, module)
    spec.loader.exec_module(module)
    return module


np = load("network_policy")
for name, value in namespace.items():
    if callable(value):
        setattr(config, name, value)
if not hasattr(config, "parse_tailscale_ssh_target"):
    raise SystemExit("parse_tailscale_ssh_target not found in config.py")
ts = load("tailscale_ssh")

ROUTES = {}
NAMES = {}
ts._route_interface_for_ip = lambda address: ROUTES.get(str(address))


def fake_getaddrinfo(host, port, family=0, type=0, *args, **kwargs):
    if host not in NAMES:
        raise socket.gaierror("not found")
    out = []
    for ip in NAMES[host]:
        fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sockaddr = (ip, port or 0, 0, 0) if fam == socket.AF_INET6 else (ip, port or 0)
        out.append((fam, socket.SOCK_STREAM, 6, "", sockaddr))
    return out


np.socket.getaddrinfo = fake_getaddrinfo

ROUTE_TABLE = {
    "100.100.100.10": "tailscale0", "100.100.100.11": "tailscale0", "100.100.100.2": "lo",
    "100.80.0.7": "lan0", "192.168.1.10": "eth0", "fd7a:115c:a1e0::10": "tailscale0",
    "fd7a:115c:a1e0::2": "lo", "2001:db8::10": "eth0", "10.0.0.5": "eth0",
}
NAME_TABLE = {
    "node.tail.ts.net": ["100.100.100.10"],
    "dual.lan": ["192.168.1.10", "100.100.100.11"],
    "lan.only": ["192.168.1.10"],
    "v6.node": ["fd7a:115c:a1e0::10", "100.100.100.10"],
    "mapped.node": ["::ffff:100.100.100.10"],
    "self.node": ["100.100.100.2", "100.100.100.10"],
    "dup.node": ["100.80.0.7", "100.80.0.7", "100.100.100.11"],
    "unrouted.node": ["100.100.100.99"],
}

CONFIGS = [
    {"enabled": True, "interface": "tailscale0", "users": ["alice", "Bob"], "remote": [],
     "targets": ["node.tail.ts.net", "100.100.100.10:22", "dual.lan:2222", "lan.only", "[fd7a:115c:a1e0::10]:22",
                 "v6.node", "mapped.node", "self.node", "dup.node", "unrouted.node", "100.80.0.7", "100.100.100.2",
                 "missing.node", "NODE.TAIL.TS.NET.", "bad target", "::ffff:100.100.100.10"]},
    {"enabled": True, "interface": "tailscale0", "users": ["alice"], "remote": ["tsuser", "root"],
     "targets": ["node.tail.ts.net", "100.100.100.10"]},
    {"enabled": True, "interface": "  ", "users": ["alice"], "remote": [], "targets": ["node.tail.ts.net"]},
    {"enabled": False, "interface": "tailscale0", "users": ["alice"], "remote": [], "targets": ["node.tail.ts.net"]},
    {"enabled": True, "interface": "tailscale0", "users": [], "remote": [], "targets": []},
]
USERS = [
    {"id": 1, "username": "alice", "is_admin": False}, {"id": 2, "username": "ALICE", "is_admin": False},
    {"id": 3, "username": "Bob", "is_admin": False}, {"id": 4, "username": "carol", "is_admin": True},
    {"id": 5, "username": "dave", "is_admin": False},
]
HOSTS = ["node.tail.ts.net", "NODE.tail.ts.net.", " node.tail.ts.net ", "100.100.100.10", "dual.lan", "lan.only",
         "fd7a:115c:a1e0::10", "[fd7a:115c:a1e0::10]", "fd7a:115c:a1e0:0::10", "v6.node", "mapped.node", "self.node",
         "dup.node", "unrouted.node", "100.80.0.7", "100.100.100.2", "missing.node", "::ffff:100.100.100.10",
         "bad host", ""]
PORTS = [22, 2222, 0, 65536]
REMOTES = ["tsuser", " tsuser ", "root", "Root", "", "　tsuser"]


class User:
    def __init__(self, record):
        self.id = record["id"]
        self.username = record["username"]
        self.is_admin = record["is_admin"]


def configure(c):
    config.TAILSCALE_SSH_ENABLED = c["enabled"]
    config.TAILSCALE_SSH_INTERFACE = c["interface"].strip()
    config.TAILSCALE_SSH_ALLOWED_WEBSSH_USERS = frozenset(c["users"])
    config.TAILSCALE_SSH_ALLOWED_REMOTE_USERS = frozenset(c["remote"])
    config.TAILSCALE_SSH_ALLOWED_TARGETS = frozenset(c["targets"])
    pairs = []
    for raw in c["targets"]:
        try:
            host, port = config.parse_tailscale_ssh_target(raw)
        except (TypeError, ValueError):
            continue
        if [host, port] not in pairs:
            pairs.append([host, port])
    return pairs


ROUTES.update(ROUTE_TABLE)
NAMES.update(NAME_TABLE)
configs = []
cases = []
rng = random.Random(20261127)
for index, c in enumerate(CONFIGS):
    configs.append({"enabled": c["enabled"], "interface": c["interface"], "users": c["users"],
                    "remote": c["remote"], "targets": configure(c)})
    combos = list(itertools.product(USERS, HOSTS, PORTS, REMOTES))
    if index > 0:
        combos = rng.sample(combos, 400)
    for record, host, port, remote in combos:
        user = User(record)
        error = ts.validate_tailscale_ssh_access(user, host, remote, port=port)
        authorization, auth_error = ts.authorize_tailscale_ssh_access(user, host, remote, port=port)
        # The saved-host check is validate_tailscale_ssh_access is None;
        # assert it here instead of storing it per case.
        assert ts.profile_is_authorized_for_launch(
            user, {"auth_type": "tailscale", "host": host, "username": remote, "port": port}) == (error is None)
        case = {"config": index, "user": record["id"], "host": host, "port": port, "remote": remote}
        if error is not None:
            case["check"] = error
        if auth_error is not None:
            case["authorize"] = auth_error
        if authorization is not None:
            case["ip"] = authorization.resolved_target.ip
            case["matches"] = {
                "same": authorization.matches(user.id, host, port, remote),
                "other_user": authorization.matches(user.id + 100, host, port, remote),
                "other_port": authorization.matches(user.id, host, port + 1, remote),
                "other_remote": authorization.matches(user.id, host, port, remote + "x"),
                "canonical": authorization.matches(user.id, host.upper() + ".", port, " " + remote + " "),
            }
        cases.append(case)

# One case per line keeps the file small and its diffs readable.
head = json.dumps({"python": sys.version.split()[0], "routes": ROUTE_TABLE, "names": NAME_TABLE, "users": USERS,
                   "configs": configs}, ensure_ascii=False, indent=1)
sys.stdout.write(head[:-2] + ',\n "cases": [\n')
sys.stdout.write(",\n".join(json.dumps(c, ensure_ascii=False, separators=(",", ":")) for c in cases))
sys.stdout.write("\n ]\n}\n")
