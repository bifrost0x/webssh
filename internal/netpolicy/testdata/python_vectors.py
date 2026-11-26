"""Record the decisions of the Python network policy as test vectors.

Usage (from the repository root, with the project virtual environment):

    .venv/bin/python -I internal/netpolicy/testdata/python_vectors.py . \
        > internal/netpolicy/testdata/python_vectors.json

app/network_policy.py and app/socks5_client.py are loaded unchanged from
the given checkout. Only their collaborators are replaced: configuration,
the admin setting, the kernel route lookup, the audit log and the resolver.
The jump-host branch of app/ssh_manager.py is not importable on its own;
jump_case() repeats its decision steps in the same order.
"""

import importlib.util
import ipaddress
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
config.TAILSCALE_SSH_ENABLED = True
config.TAILSCALE_SSH_INTERFACE = "tailscale0"
sys.modules["config"] = config

settings = types.ModuleType("app.app_settings")
settings.is_tailnet_route_restricted = lambda: True
sys.modules["app.app_settings"] = settings

ROUTES = {}
tailscale = types.ModuleType("app.tailscale_ssh")
tailscale._route_interface_for_ip = lambda address: ROUTES.get(address)
sys.modules["app.tailscale_ssh"] = tailscale
package.tailscale_ssh = tailscale

audit = types.ModuleType("app.audit_logger")
audit.log_info = lambda *args, **kwargs: None
sys.modules["app.audit_logger"] = audit


def load(name):
    spec = importlib.util.spec_from_file_location(f"app.{name}", root / "app" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"app.{name}"] = module
    setattr(package, name, module)
    spec.loader.exec_module(module)
    return module


np = load("network_policy")
socks = load("socks5_client")

NAMES = {}


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

# Deterministic address corpus: the edges of every special block, mapped
# and scoped forms, and random addresses.
blocks = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.0.8/29", "192.0.0.170/31", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
    "::/128", "::1/128", "::/8", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48",
    "100::/64", "100::/8", "200::/7", "2001::/23", "2001:1::/48", "2001:3::/32",
    "2001:4:112::/48", "2001:10::/28", "2001:20::/28", "2001:30::/28", "2001:db8::/32",
    "2002::/16", "3fff::/20", "fc00::/7", "fd7a:115c:a1e0::/48",
    "fd7a:115c:a1e0:b1a::/64", "fe80::/10", "fec0::/10", "fe00::/9", "ff00::/8",
    "4000::/3", "e000::/4", "f000::/5", "f800::/6",
]
addresses = set()
for block in blocks:
    net = ipaddress.ip_network(block)
    first, last = int(net.network_address), int(net.broadcast_address)
    top = (1 << net.max_prefixlen) - 1
    for value in (first, last, first - 1, last + 1, (first + last) // 2):
        if 0 <= value <= top:
            addresses.add(str(ipaddress.ip_address(value) if net.version == 4 else ipaddress.IPv6Address(value)))
rng = random.Random(20261126)
for _ in range(500):
    addresses.add(str(ipaddress.IPv4Address(rng.getrandbits(32))))
    addresses.add(str(ipaddress.IPv6Address(rng.getrandbits(128))))
    addresses.add(str(ipaddress.IPv6Address((0xFFFF << 32) | rng.getrandbits(32))))
for v4 in ["8.8.8.8", "10.1.2.3", "100.100.100.10", "127.0.0.1", "169.254.169.254", "192.168.1.1"]:
    addresses.add("::ffff:" + v4)
addresses = sorted(addresses)

allow = (ipaddress.ip_network("10.20.0.0/16"), ipaddress.ip_network("100.64.0.0/10"),
         ipaddress.ip_network("fd00::/8"), ipaddress.ip_network("192.168.0.0/16"))

classify = []
for text in addresses:
    address = ipaddress.ip_address(text)
    classify.append({
        "addr": text,
        "internal": np._ip_is_internal(address),
        "allowlisted": np._ip_in_internal_allowlist(address, allow),
        "node": np._tailscale_node_address(text) is not None,
    })

host_inputs = [
    "Example.COM.", "example.com..", " [fd7a::1] ", "fd7a:0::1", "100.064.0.1", "::ffff:1.2.3.4",
    "::FFFF:0102:0304", "::1.2.3.4", "1:0:0:2:0:0:0:3", "1:0:0:0:2:0:0:3", "fe80::1%eth0",
    "fe80::1%", "fe80::1%a%b", "[fe80::1%eth0]", "a_b", "bücher.de", "", ".", "..", "x" * 254,
    "a" * 63 + ".com", "a" * 64 + ".com", ("a" * 63 + ".") * 4, "0x7f.1", "01.2.3.4",
    "1.2.3.04", "-a.b", "a-.b", "a..b", "　host　", "\thost\n", "host\x1c",
    "[host]", "[[host]]", "host.", "HOST", "*.lan", "a.b-c.d", "123", "1.2.3", "1.2.3.4.5",
    "::", "0:0::0", "2001:DB8::1", "::ffff:100.100.100.10", "[::1]", "[::1]:22", "h​x",
    "a" * 253, "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 61,
]
canonical = []
for value in host_inputs:
    try:
        canonical.append({"in": value, "ok": True, "out": np.canonicalize_hostname(value)})
    except ValueError:
        canonical.append({"in": value, "ok": False})


def configure(tailnet, routes, names):
    config.TAILSCALE_SSH_ENABLED = tailnet
    ROUTES.clear()
    ROUTES.update(routes)
    NAMES.clear()
    NAMES.update(names)


def outcome(fn):
    try:
        result = fn()
    except np.TailnetRouteRestricted:
        return {"ok": False, "error": "tailnet"}
    except ValueError as error:
        text = str(error)
        kind = "unresolved" if "resolved" in text else "blocked" if "not allowed" in text else "invalid"
        return {"ok": False, "error": kind}
    if isinstance(result, socks.RemoteName):
        return {"ok": True, "name": result.hostname}
    if isinstance(result, np.ResolvedTarget):
        return {"ok": True, "ip": result.ip, "via": result.via_internal_allowlist}
    return {"ok": True}


ROUTE_TABLE = {
    "100.100.100.10": "tailscale0", "100.100.100.2": "lo", "100.80.0.7": "lan0",
    "fd7a:115c:a1e0::9": "tailscale0", "8.8.8.8": "eth0", "10.20.1.1": "eth0",
    "192.168.1.5": "eth0", "203.0.113.9": "eth0", "127.0.0.1": "lo", "192.168.1.1": "lo",
}
NAME_TABLE = {
    "public.example": ["203.0.113.9", "8.8.8.8"], "lan.example": ["192.168.1.5"],
    "mixed.example": ["192.168.1.5", "8.8.8.8"], "node.example": ["100.100.100.10"],
    "node-then-public.example": ["100.100.100.10", "8.8.8.8"], "cgnat.example": ["100.80.0.7"],
    "unknown-route.example": ["100.99.0.1"], "allowed.example": ["10.20.1.1"],
    "loop.example": ["127.0.0.1"], "self.example": ["100.100.100.2"],
    "mapped.example": ["::ffff:100.100.100.10"], "v6node.example": ["fd7a:115c:a1e0::9"],
    "via.example": ["fd7a:115c:a1e0:b1a::1"], "dup.example": ["192.168.1.5", "192.168.1.5"],
}
targets = sorted(NAME_TABLE) + [
    "nxdomain.example", "magic.tail1234.ts.net", "ts.net", "100.100.100.10", "100.80.0.7",
    "100.99.0.1", "::ffff:100.100.100.10", "8.8.8.8", "192.168.1.5", "10.20.1.1", "127.0.0.1",
    "169.254.169.254", "fe80::1%eth0", "fd7a:115c:a1e0:b1a::1", "Public.Example.",
]
modes = [
    {"block": False, "allow": [], "tailnet": False, "jump_dns": [], "socks_dns": []},
    {"block": False, "allow": [], "tailnet": True, "jump_dns": [], "socks_dns": []},
    {"block": True, "allow": [], "tailnet": False, "jump_dns": [], "socks_dns": []},
    {"block": True, "allow": ["10.20.0.0/16", "100.64.0.0/10"], "tailnet": True,
     "jump_dns": ["nxdomain.example", "lan.example"], "socks_dns": ["lan.example", "magic.tail1234.ts.net"]},
]


def jump_case(host, mode):
    """The decision steps of the jump-host branch of app/ssh_manager.py."""
    host = np.canonicalize_hostname(host)
    try:
        target = np.resolve_allowed_target(host, 22, allow_internal=not mode["block"],
                                           allowed_internal_networks=mode["nets"])
        return target
    except np.TailnetRouteRestricted:
        raise
    except ValueError:
        if mode["block"] and not np.proxy_jump_remote_dns_allowed(host, mode["jump_dns"]):
            raise ValueError("Connections to this address are not allowed") from None
        np.check_remote_name(host)
        return socks.RemoteName(host, 22)


cases = []
for mode in modes:
    mode = dict(mode, nets=tuple(ipaddress.ip_network(n) for n in mode["allow"]))
    configure(mode["tailnet"], ROUTE_TABLE, NAME_TABLE)
    for host in targets:
        entry = {"mode": {k: mode[k] for k in ("block", "allow", "tailnet", "jump_dns", "socks_dns")}, "host": host}
        entry["target"] = outcome(lambda: np.resolve_allowed_target(
            host, 22, allow_internal=not mode["block"], allowed_internal_networks=mode["nets"]))
        relay = outcome(lambda: np.resolve_allowed_target(
            host, 22, allow_internal=not mode["block"], allowed_internal_networks=mode["nets"]))
        if relay["ok"]:
            relay = outcome(lambda: np.check_relay_endpoint(np.resolve_allowed_target(
                host, 22, allow_internal=not mode["block"], allowed_internal_networks=mode["nets"])))
        entry["relay"] = relay
        entry["jump"] = outcome(lambda: jump_case(host, mode))
        for remote_dns in (True, False):
            entry[f"socks_{str(remote_dns).lower()}"] = outcome(lambda: np.socks_destination(
                host, 22, remote_dns, allow_internal=not mode["block"],
                allowed_internal_networks=mode["nets"], remote_dns_allowlist=mode["socks_dns"]))
        cases.append(entry)

json.dump({"routes": ROUTE_TABLE, "names": NAME_TABLE, "classify": classify,
           "canonical": canonical, "cases": cases}, sys.stdout, ensure_ascii=False, indent=0)
sys.stdout.write("\n")
