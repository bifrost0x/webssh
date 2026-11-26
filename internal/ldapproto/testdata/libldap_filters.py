"""Record how the Python release encodes LDAP search filters.

Usage (from the repository root, with the project virtual environment and
the libldap of the Python image, OpenLDAP 2.6):

    .venv/bin/python -I internal/ldapproto/testdata/libldap_filters.py . \
        > internal/ldapproto/testdata/libldap_filters.json

The Python release builds the filter with escape_filter_value of
app/ldap_service.py and hands the string to Bonsai, which passes it to
ldap_search_ext of libldap; libldap encodes it with ldap_pvt_put_filter.
This script loads escape_filter_value unchanged from the given checkout
and calls ldap_pvt_put_filter through ctypes, so the vectors hold the
octets libldap puts on the wire, or null where libldap refuses the
filter (Bonsai then raises FilterError, which the release reports as an
unavailable directory).
"""

import ctypes
import ctypes.util
import importlib.util
import json
import pathlib
import random
import sys

root = pathlib.Path(sys.argv[1]).resolve()
spec = importlib.util.spec_from_file_location("ldap_service", root / "app" / "ldap_service.py")
ldap_service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ldap_service)
escape = ldap_service.escape_filter_value

lber = ctypes.CDLL(ctypes.util.find_library("lber") or "liblber.so.2")
libldap = ctypes.CDLL(ctypes.util.find_library("ldap") or "libldap.so.2")


class BerVal(ctypes.Structure):
    _fields_ = [("bv_len", ctypes.c_ulong), ("bv_val", ctypes.c_void_p)]


lber.ber_alloc_t.restype = ctypes.c_void_p
lber.ber_alloc_t.argtypes = [ctypes.c_int]
lber.ber_flatten.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(BerVal))]
lber.ber_free.argtypes = [ctypes.c_void_p, ctypes.c_int]
lber.ber_bvfree.argtypes = [ctypes.POINTER(BerVal)]
libldap.ldap_pvt_put_filter.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
libldap.ldap_pvt_put_filter.restype = ctypes.c_int
LBER_USE_DER = 0x01


def encode(text):
    ber = lber.ber_alloc_t(LBER_USE_DER)
    try:
        if libldap.ldap_pvt_put_filter(ber, text.encode("utf-8")) == -1:
            return None
        flat = ctypes.POINTER(BerVal)()
        if lber.ber_flatten(ber, ctypes.byref(flat)) != 0:
            raise RuntimeError("ber_flatten failed")
        try:
            return ctypes.string_at(flat.contents.bv_val, flat.contents.bv_len).hex()
        finally:
            lber.ber_bvfree(flat)
    finally:
        lber.ber_free(ber, 1)


HAND = [
    "(uid=alice)", "uid=alice", " (uid=a)", "(& (uid=a) (cn=b))", "(&\t(uid=a)\n(cn=b))",
    "(&\r(uid=a))", "(\x0buid=a)", "( uid=a)", "(\tuid=a)", "(uid =a)", "(uid= a)", "(uid=a )",
    "(uid=a*b)", "(uid=*a*b*)", "(uid=a**b)", "(uid=**)", "(uid=*)", "(uid=\\2a)", "(uid=\\*)",
    "(uid=\\(\\))", "(uid=\\\\)", "(uid=\\5c)", "(uid=\\a)", "(uid=\\4)", "(uid=\\4g)", "(uid=a\\)",
    "(&)", "(|)", "(!)", "(& )", "(! (a=b) )", "(!(a=b)(c=d))", "(!(a=b))", "(uid=a)(cn=b)",
    "(uid=a))", "(uid=a", "uid=a)", "((uid=a))", ")", ")(uid=a)", "(", "", " ", "  ",
    "(uid:dn:2.5.13.5:=x)", "(uid:DN:=x)", "(uid::=x)", "(:=x)", "(:dn:=x)", "(:2.5:=x)",
    "(uid:x:y:=z)", "(uid:dn:x:=z)", "(uid:dn:1..2:=z)", "(uid:1.:=z)", "(:dn:2.5:=x)",
    "(memberOf:1.2.840.113556.1.4.1941:=cn=x,dc=y)", "(uid:=*)", "(uid:=a*)",
    "(2=a)", "(01.2=a)", "(1.2.=a)", "(1..2=a)", "(a;-x=b)", "(a;=b)", "(a;b;=c)", "(1.2;x=a)",
    "(1.;x=a)", "(u_id=a)", "(1uid=a)", "(=a)", "(<=a)", "(uid<=5)", "(uid>=5)", "(uid~=5)",
    "(uid<=*)", "(uid>=a*)", "(uid~=)", "(uid=)", "(uid=a=b)", "(uid=a(b))", "(uid=a)b)",
    "(&(uid=a)(|(cn=b)(!(sn=c))))", "(&(uid=a)(cn=b)", "(uid=a)x", "(&(uid=a))x",
    "(&(objectClass=inetOrgPerson)(uid=alice))", "(|(&)(uid=a))", "(&x(uid=a))", "(&(uid=a)x)",
    "(cn=\\00)", "(cn=caf\\c3\\a9)", "(cn=é)", "(sAMAccountName=alice)",
    "(&(objectCategory=person)(objectClass=user)(sAMAccountName=alice))",
    "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
]

TEMPLATES = [
    "(uid={username})",
    "uid={username}",
    "(&(objectClass=inetOrgPerson)(uid={username}))",
    "(&(objectClass=person)(|(uid={username})(mail={username})))",
    "(&(objectCategory=person)(objectClass=user)(sAMAccountName={username}))",
    "(&(sAMAccountName={username})(memberOf:1.2.840.113556.1.4.1941:=cn=WebSSH,ou=Groups,dc=example,dc=com))",
    "(cn={username}*)",
    "(& (uid={username}) (objectClass=*))",
]

USERNAMES = [
    "alice", "a*", "*", ")(uid=*", "\\", "\x00", "é", "日本", "a b", "(", ")", "a\\2a",
    "x" * 256, "\U0001f600", "o'brien", "a,b=c", "\t", "uid=*)(|(uid=*",
]

ATOMS = ["uid", "cn", "2.5.4.3", "a;b", "x-y", "01.2", "u_d", "", "1.", "a;"]
OPS = ["=", "~=", ">=", "<=", ":=", ":dn:=", ":2.5:=", ":dn:2.5:=", "::=", ""]
VALUES = ["a", "*", "a*b", "**", "", "\\2a", "\\*", "\\", "\\4", "(", ")", "a b", "=", "\\(", "é", "\\5C"]


def random_item(rng):
    return rng.choice(ATOMS) + rng.choice(OPS) + rng.choice(VALUES)


def random_filter(rng, depth=0):
    roll = rng.random()
    if depth > 3 or roll < 0.45:
        body = random_item(rng)
        pad = rng.choice(["", "", "", " ", "\t", "\n"])
        return "(" + pad + body + ")" if rng.random() < 0.9 else body
    op = rng.choice("&|!")
    members = [random_filter(rng, depth + 1) for _ in range(rng.choice([0, 1, 1, 2, 3]))]
    sep = rng.choice(["", "", " ", "\n"])
    return "(" + op + sep.join(members) + ")"


def mutate(rng, text):
    chars = list(text)
    for _ in range(rng.randint(1, 3)):
        if not chars:
            break
        pos = rng.randrange(len(chars))
        action = rng.random()
        if action < 0.4:
            del chars[pos]
        elif action < 0.8:
            chars.insert(pos, rng.choice("()&|!*=\\: \t\na1;.-"))
        else:
            chars[pos] = rng.choice("()&|!*=\\: \t\na1;.-")
    return "".join(chars)


def main():
    rng = random.Random(4515)
    filters = list(HAND)
    for template in TEMPLATES:
        for name in USERNAMES:
            filters.append(template.replace("{username}", escape(name)))
    for _ in range(3000):
        filters.append(random_filter(rng))
    for _ in range(3000):
        filters.append(mutate(rng, rng.choice(filters[: len(HAND)] + TEMPLATES)))
    seen = set()
    vectors = []
    for f in filters:
        if f in seen or "\x00" in f:
            continue
        seen.add(f)
        vectors.append({"filter": f, "ber": encode(f)})
    escapes = []
    for name in USERNAMES + ["".join(chr(rng.randrange(1, 0x2FFF)) for _ in range(rng.randint(1, 12))) for _ in range(500)]:
        escapes.append({"value": name, "escaped": escape(name)})
    json.dump({"filters": vectors, "escapes": escapes}, sys.stdout, ensure_ascii=True, indent=0)
    sys.stdout.write("\n")


main()
