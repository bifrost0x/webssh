"""Generate LDAP subject vectors from the WebSSH 3.x code path.

Bonsai's berval2PyObject (bonsai 1.5.5, src/_bonsai/utils.c, keepbytes=0)
is emulated in Python; _canonical_subject is loaded from app/ldap_service.py.
Usage (from the repository root, with the venv in $WEBSSH_PYTHON_ROOT):

    $WEBSSH_PYTHON_ROOT/.venv/bin/python -I internal/auth/ldap/testdata/python_subjects.py \
        "$WEBSSH_PYTHON_ROOT"/app/ldap_service.py internal/auth/ldap/testdata/python_subjects.json
"""
import importlib.util
import json
import random
import sys


def bonsai_value(raw):
    cstr = raw.split(b"\0", 1)[0]
    if cstr == b"TRUE":
        return True
    if cstr == b"FALSE":
        return False
    try:
        return int(cstr, 0)
    except ValueError:
        pass
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw


def main():
    spec = importlib.util.spec_from_file_location("ldap_service", sys.argv[1])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fixed = [
        b"afc8b795-5c9d-454c-988a-bd4184efdb5e", b"TRUE", b"FALSE", b"true",
        b"TRUE\0x", b"42", b"042", b"00", b"0", b"-0", b"+7", b" 12 ", b"\t9\n",
        b"0x1F", b"0X_ff", b"0o17", b"0b101", b"0b", b"0x", b"1_000", b"1__0",
        b"_1", b"1_", b"12abc", b"5\0rest", b"\0", b"", b" ", b"\x1c a \x1f",
        b"\xc2\xa0x\xc2\xa0", b"\xe2\x80\x83y", b"\x85z", b"caf\xc3\xa9",
        b"\xff\xfe\x00\x01", bytes(range(16)), b"\x80" * 16, b"a" * 512,
        b"a" * 513, b"\xc3\xa9" * 512, b"\xc3\xa9" * 513, b"\xff" * 400,
        b"9" * 4300, b"9" * 4301, b"0x" + b"f" * 300, b"\xd9\xa1\xd9\xa2",
        b"S-1-5-21", b"1.5", b"1e3", b"--1", b"+-1", b"0_0", b"0_1", b"\v42\f",
    ]
    rng = random.Random(20261126)
    for _ in range(3000):
        n = rng.choice([1, 2, 3, 4, 8, 16, 16, 16, 36])
        alphabet = rng.choice([None, b"0123456789_ xXoObB+-", b"TRUEFALS\0 "])
        if alphabet is None:
            fixed.append(bytes(rng.randrange(256) for _ in range(n)))
        else:
            fixed.append(bytes(rng.choice(alphabet) for _ in range(n)))
    out = []
    for raw in fixed:
        try:
            result = module._canonical_subject(bonsai_value(raw))
            out.append({"raw": raw.hex(), "subject": result})
        except module.LDAPLookupRejected:
            out.append({"raw": raw.hex(), "rejected": True})
        except ValueError as exc:
            out.append({"raw": raw.hex(), "python_error": type(exc).__name__})
    with open(sys.argv[2], "w", encoding="utf-8") as handle:
        json.dump(out, handle, ensure_ascii=True, indent=0)


if __name__ == "__main__":
    main()
