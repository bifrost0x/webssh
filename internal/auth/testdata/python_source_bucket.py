"""Record rate_limit_address of the Python release as test vectors.

Usage (from the repository root, with the venv in $WEBSSH_PYTHON_ROOT):

    $WEBSSH_PYTHON_ROOT/.venv/bin/python -I internal/auth/testdata/python_source_bucket.py "$WEBSSH_PYTHON_ROOT" \
        > internal/auth/testdata/python_source_bucket.json

The function is taken unchanged from app/auth.py (by its syntax tree);
only the sign-in protection setting it reads is replaced.
"""

import ast
import ipaddress
import json
import pathlib
import random
import sys
import types

root = pathlib.Path(sys.argv[1]).resolve()
source = (root / "app" / "auth.py").read_text(encoding="utf-8")
tree = ast.parse(source)
func = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "rate_limit_address")

prefix = {"value": 128}
package = types.ModuleType("app")
package.__path__ = []
settings = types.ModuleType("app.app_settings")
settings.ratelimit_ipv6_prefix = lambda: prefix["value"]
sys.modules["app"] = package
sys.modules["app.app_settings"] = settings
scope = {"__name__": "app.auth", "__package__": "app", "ipaddress": ipaddress}
exec(compile(ast.Module(body=[func], type_ignores=[]), "app/auth.py", "exec"), scope)
rate_limit_address = scope["rate_limit_address"]

inputs = [
    "10.0.0.1", " 10.0.0.1 ", "::ffff:10.0.0.1", "::ffff:a00:1", "2001:db8::1", "2001:DB8::1",
    "2001:db8:0:0:ffff::1", "2001:db8:abcd:1234:5678:9abc:def0:1234", "::1", "::", "fe80::1",
    "fe80::1%eth0", "not-an-ip", "", "unknown", "1.2.3", "2001:db8::/64", "::ffff:192.0.2.128",
    "64:ff9b::192.0.2.1", "2002:c000:0204::1",
]
rng = random.Random(4)
for _ in range(200):
    inputs.append(str(ipaddress.IPv6Address(rng.getrandbits(128))))
    inputs.append(str(ipaddress.IPv4Address(rng.getrandbits(32))))

out = []
for p in (48, 56, 64, 72, 96, 112, 127, 128):
    prefix["value"] = p
    for value in inputs:
        out.append({"in": value, "prefix": p, "want": rate_limit_address(value)})
sys.stdout.write("[\n" + ",\n".join(json.dumps(o, sort_keys=True) for o in out) + "\n]\n")
