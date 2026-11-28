"""Record the rules of the Python SMB modules as test vectors.

Usage (from the repository root, with the venv in $WEBSSH_PYTHON_ROOT):

    $WEBSSH_PYTHON_ROOT/.venv/bin/python -I internal/files/smb/testdata/python_vectors.py "$WEBSSH_PYTHON_ROOT" \
        > internal/files/smb/testdata/python_vectors.json

app/smb_paths.py, app/smb_share_manager.py, app/smb_pool.py,
app/smb_protocol.py and app/smb_network_policy.py are loaded unchanged
from the given checkout. Only collaborators are replaced: configuration,
storage, the quota manager, the protocol client of the pool and the
resolver.
"""

import datetime
import importlib.util
import json
import pathlib
import socket
import sys
import types

root = pathlib.Path(sys.argv[1]).resolve()

package = types.ModuleType("app")
package.__path__ = [str(root / "app")]
sys.modules["app"] = package

config = types.ModuleType("config")
config.SMB_MAX_SAVED_SHARES = 100
config.SMB_ALLOWED_TARGETS = ()
config.SMB_CONNECT_TIMEOUT_SECONDS = 10
config.SMB_IO_IDLE_TIMEOUT_SECONDS = 30
config.MAX_TRANSFER_MEMBERS = 10000
sys.modules["config"] = config


def stub(name, **attrs):
    module = types.ModuleType(f"app.{name}")
    for key, value in attrs.items():
        setattr(module, key, value)
    sys.modules[f"app.{name}"] = module
    setattr(package, name, module)
    return module


stub("storage_migrations", CURRENT_STORAGE_VERSIONS={"smb_shares": 2})
stub("storage_utils", atomic_write_json=None, load_json_migrated=None, storage_lock=None)
stub("data_access", user_operation=lambda f: f)
stub("audit_logger", log_info=lambda *a, **k: None)
stub("tailscale_ssh", _route_interface_for_ip=lambda address: None)
stub("app_settings", is_tailnet_route_restricted=lambda: False, runtime_feature_enabled=lambda name: False)


class QuotaExceeded(Exception):
    pass


stub("quota_manager", QuotaExceeded=QuotaExceeded,
     QuotaKind=types.SimpleNamespace(QUICK_CONNECTION="quick_connection"),
     quota_manager=None, release_reservation=lambda r: None)


def load(name):
    spec = importlib.util.spec_from_file_location(f"app.{name}", root / "app" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"app.{name}"] = module
    setattr(package, name, module)
    spec.loader.exec_module(module)
    return module


np = load("network_policy")
paths = load("smb_paths")
diagnostics = load("smb_diagnostics")
policy = load("smb_network_policy")
manager = load("smb_share_manager")
load("file_backend")
load("file_sources")
protocol = load("smb_protocol")
pool = load("smb_pool")


def outcome(fn):
    try:
        return {"ok": True, "value": fn()}
    except Exception as exc:  # the type is the vector
        return {"ok": False, "error": type(exc).__name__, "code": getattr(exc, "public_code", None)}


components = [
    "a", "a.txt", "dir name", "Ünïcødé", "trailing.", "trailing ", ".", "..", "", "con", "CON.txt", "com1",
    "COM0", "lpt9.log", "nul", "aux.", "prn", "a<b", "a>b", "a:b", 'a"b', "a/b", "a\\b", "a|b", "a?b", "a*b",
    "tab\tname", "bell\x07", "del\x7f", "share$", "$", "x" * 80, "x" * 81, "y" * 255, "y" * 256, "ä" * 255,
    "ä" * 256, "​", " lead", "😀", "C$", "IPC$", "Admin$", "conin$", "CON .txt",
]
path_inputs = ["/", "", "a", "/a", "/a/", "//a", "/a//b", "/a/b/c", "/a/./b", "/a/../b", "/" + "/".join(["p"] * 128),
               "/" + "/".join(["p"] * 129), "/" + "a" * 4095, "/" + "a" * 4096, "/" + "ä" * 2000,
               "/x/CON", "/x/share$", "/x/tab\tx", "/ä/ö"] + ["/" + c for c in components]
vectors = {
    "share_names": [{"in": c, **outcome(lambda c=c: str(paths.SMBShareName.parse(c)))} for c in components],
    "paths": [{"in": p, **outcome(lambda p=p: list(paths.SMBPath.parse(p).segments))} for p in path_inputs],
}

secret_names = ["password", "Password", "pass_word", "PASSWD", "passphrase", "credential_id", "x-secret", "api_token",
                "tokenizer", "name", "host", "user", "pass", "pwd", "SeCrEt", "créd", "pass-word", "pass word",
                "credentials", "my_password_hint"]
vectors["secret_fields"] = [{"in": n, "secret": manager._is_secret_field(n)} for n in secret_names]

base = {"name": "NAS", "host": "nas.example", "share": "Data", "domain": "", "username": "alice"}
variants = [
    {}, {"name": "  NAS  "}, {"name": ""}, {"name": "   "}, {"name": "x" * 128}, {"name": "x" * 129},
    {"name": "a\x00b"}, {"name": "tab\tname"}, {"name": " nbsp "}, {"name": "\x1cname\x1f"},
    {"name": "zero​width"}, {"name": "é"}, {"name": 5}, {"name": None},
    {"host": "NAS.Example."}, {"host": "10.0.0.5"}, {"host": "[fe80::1]"}, {"host": "fe80::1"}, {"host": "bad host"},
    {"host": ""}, {"host": "a" * 254}, {"host": "-x.example"}, {"host": "x_y.example"}, {"host": 7},
    {"share": "C$"}, {"share": "con"}, {"share": "a" * 81}, {"share": " Data"}, {"share": "Data "},
    {"domain": None}, {"domain": "  LAB  "}, {"domain": "d" * 255}, {"domain": "d" * 256}, {"domain": "LAB\x01"},
    {"username": ""}, {"username": " bob "}, {"username": "u" * 256}, {"username": "u" * 257},
    {"username": "dom\\user"}, {"username": "ü"}, {"id": "abc"}, {"id": "a" * 65}, {"id": "bad id"}, {"id": 5},
    {"password": "x"}, {"api_token": ""}, {"Credential": None},
]
payloads = []
for v in variants:
    p = dict(base)
    p.update(v)
    if v == {"domain": None}:
        p["domain"] = None
    payloads.append(p)
payloads.append({k: v for k, v in base.items() if k != "domain"})
payloads.append({k: v for k, v in base.items() if k != "username"})
vectors["payloads"] = []
for p in payloads:
    validated, error = manager._validate_payload(p)
    vectors["payloads"].append({"in": p, "validated": validated, "error": error})

stored = dict(base, id="0123456789abcdef0123456789abcdef", created_at="2026-01-01T00:00:00+00:00",
              updated_at="2026-01-01T00:00:00+00:00")
record_variants = [{}, {"host": "NAS.example"}, {"name": " NAS"}, {"extra": 1}, {"extra_token": "x"}, {"id": "bad id"},
                   {"created_at": ""}, {"updated_at": 5}, {"domain": " LAB"}, {"share": "C$"}]
records = []
for v in record_variants:
    r = dict(stored)
    r.update(v)
    records.append(r)
records.append({k: v for k, v in stored.items() if k != "domain"})
records.append({k: v for k, v in stored.items() if k != "created_at"})
vectors["records"] = [{"in": r, "valid": manager._valid_share(r)} for r in records]


class FakeSession:
    def __init__(self):
        self.raw_connection = types.SimpleNamespace(transport=types.SimpleNamespace(connected=True))

    def inspect_directory_access(self, unc):
        return {"list": "granted"}

    def close(self):
        pass


class FakeClient:
    def connect(self, **kwargs):
        return FakeSession()


class FakeQuota:
    def reserve(self, kind, user):
        return object()


resolved = np.ResolvedTarget("nas.example", 445, "192.0.2.10", socket.AF_INET, ("192.0.2.10", 445))
smb_pool = pool.SMBConnectionPool(protocol_client=FakeClient(), target_resolver=lambda host, allowed: resolved,
                                  allowed_targets=("nas.example",), quota_manager=FakeQuota())
good = {"host": "nas.example", "share": "Data", "domain": "", "username": "alice", "password": "pw"}
connect_variants = [
    {}, {"username": ""}, {"password": ""}, {"username": "", "password": ""}, {"username": "a\\b"},
    {"username": "a/b"}, {"username": "u" * 256}, {"username": "u" * 257}, {"username": "tab\tuser"},
    {"username": "del\x7f"}, {"domain": "LAB"}, {"domain": "L\\A"}, {"domain": "L@A"}, {"domain": "L/A"},
    {"domain": "d" * 255}, {"domain": "d" * 256}, {"domain": None}, {"password": "p" * 4096},
    {"password": "p" * 4097}, {"password": "line\nbreak"}, {"password": "ü"}, {"share": "C$"},
    {"share": "a" * 81}, {"username": None}, {"password": None},
]
vectors["connect"] = []
for v in connect_variants:
    args = dict(good)
    args.update(v)

    def run(args=args):
        smb_pool.create_source(user_id="1", **args)
        return "ok"

    vectors["connect"].append({"in": args, **outcome(run)})


class FakeSMBOSError(protocol.SMBOSError):
    def __init__(self, status):
        Exception.__init__(self, "x")
        self.ntstatus = status


statuses = [0xC000006D, 0xC000006A, 0xC0000071, 0xC0000072, 0xC000006E, 0xC0000022, 0xC0000061, 0xC00000CA,
            0xC00000A2, 0xC0000034, 0xC000003A, 0xC0000225, 0xC000000F, 0xC0000033, 0xC00000CC, 0xC0000035,
            0xC0000043, 0xC0000101, 0xC00000BA, 0xC0000103, 0xC0000056, 0xC0000121, 0xC00000B5, 0x8000002D,
            0xC0000128, 0xC00000C9, 0xC0000203, 0xC0000001, 0xC000009A, 0xC00000BB]
vectors["statuses"] = []
for status in statuses:
    mapped = protocol._mapped_protocol_error(FakeSMBOSError(status))
    vectors["statuses"].append({"status": status, "code": mapped.public_code if mapped else None,
                                "nt_status": diagnostics._safe_nt_status(status)})

allow_cases = [
    ("nas.example", ["nas.example"]), ("NAS.EXAMPLE.", ["nas.example"]), ("nas.example", ["NAS.example"]),
    ("other.example", ["nas.example"]), ("8.8.4.4", ["8.8.4.4"]), ("8.8.4.004", ["8.8.4.4"]),
    ("2606:4700::1111", ["2606:4700:0::1111"]), ("[2606:4700::1111]", ["2606:4700::1111"]), ("8.8.4.4", ["nas.example"]),
    ("nas.example", []), ("nas.example", ["nas.example", " "]),
]


def fake_getaddrinfo(host, port, family=0, type=0, *args, **kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]


policy.socket.getaddrinfo = fake_getaddrinfo
vectors["allowlist"] = []
for host, allowed in allow_cases:
    vectors["allowlist"].append({"host": host, "allowed": allowed,
                                 **outcome(lambda h=host, a=allowed: policy.resolve_allowed_smb_target(h, a).hostname)})

times = [datetime.datetime(2026, 11, 27, 10, 0, 0, 0, tzinfo=datetime.timezone.utc),
         datetime.datetime(2026, 11, 27, 10, 0, 0, 1, tzinfo=datetime.timezone.utc),
         datetime.datetime(2026, 11, 27, 10, 0, 0, 123456, tzinfo=datetime.timezone.utc)]
vectors["times"] = [{"unix_ns": int(t.timestamp()) * 1_000_000_000 + t.microsecond * 1000, "iso": t.isoformat()} for t in times]

json.dump(vectors, sys.stdout, indent=1, sort_keys=True, ensure_ascii=False)
sys.stdout.write("\n")
