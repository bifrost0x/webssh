"""Ask the kernel through the Python release's route lookup.

Runs inside a network namespace (netns-test.sh): _route_interface_for_ip
is lifted unchanged from app/tailscale_ssh.py with ast and asked for each
address on the command line; the answers go to stdout as JSON
(address -> interface name or null).
"""
import ast
import ipaddress
import json
import socket
import struct
import sys

source = open(sys.argv[1]).read()
tree = ast.parse(source)
namespace = {"socket": socket, "struct": struct, "ipaddress": ipaddress}
wanted = {"_align_netlink", "_netlink_attribute", "_route_interface_for_ip"}
for node in tree.body:
    if isinstance(node, ast.Assign) and all(isinstance(t, ast.Name) and t.id.startswith("_") for t in node.targets):
        exec(compile(ast.Module([node], []), "tailscale_ssh.py", "exec"), namespace)
    elif isinstance(node, ast.FunctionDef) and node.name in wanted:
        exec(compile(ast.Module([node], []), "tailscale_ssh.py", "exec"), namespace)
lookup = namespace["_route_interface_for_ip"]
json.dump({address: lookup(address) for address in sys.argv[2:]}, sys.stdout)
