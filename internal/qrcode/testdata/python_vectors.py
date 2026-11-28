"""Write python_vectors.json: QR matrices of the Python release's library.

Run with the venv of the Python release (qrcode as pinned in
requirements.txt):

    $WEBSSH_PYTHON_ROOT/.venv/bin/python -I internal/qrcode/testdata/python_vectors.py
"""

import hashlib
import io
import json
import pathlib
import random
import sys
from urllib.parse import quote, urlencode

import qrcode
from qrcode.image.svg import SvgPathImage

LEVELS = {
    "L": qrcode.constants.ERROR_CORRECT_L,
    "M": qrcode.constants.ERROR_CORRECT_M,
    "Q": qrcode.constants.ERROR_CORRECT_Q,
    "H": qrcode.constants.ERROR_CORRECT_H,
}
BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def uri(secret, name):
    # Same construction as app/totp_service.py:_provisioning_uri.
    query = urlencode({"secret": secret, "issuer": "WebSSH"}).replace("+", "%20")
    return f"otpauth://totp/{quote('WebSSH')}:{quote(name)}?{query}"


def inputs():
    rng = random.Random(6238)
    yield b""
    yield b"0"
    yield b"01234567"
    yield b"HELLO WORLD"
    yield b"hello world"
    yield "Grüße, 世界".encode()
    yield b"1" * 19 + b"x"
    yield b"x" + b"1" * 20 + b"y"
    yield b"a" + b"ABCDEFGHIJKLMNOPQRST" + b"b"
    yield b"12345678901234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ" * 2
    yield bytes(range(256))
    for n in (40, 100, 200, 300, 500, 800, 1200, 1800, 2300):
        yield bytes(rng.randrange(256) for _ in range(n))
        yield "".join(rng.choice("0123456789") for _ in range(n)).encode()
        yield "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 $%*+-./:") for _ in range(n)).encode()
    names = ["admin", "alice", "bob.smith", "user name", "üser", "ad/min", "x" * 64, "测试"]
    for name in names:
        for _ in range(3):
            secret = "".join(rng.choice(BASE32) for _ in range(32))
            yield uri(secret, name).encode()


def svg(data):
    image = qrcode.make(data, image_factory=SvgPathImage)
    out = io.BytesIO()
    image.save(out)
    return out.getvalue()


def main():
    vectors = []
    for data in inputs():
        for name, level in LEVELS.items():
            qr = qrcode.QRCode(error_correction=level, border=0)
            qr.add_data(data)
            try:
                qr.make()
            except (qrcode.exceptions.DataOverflowError, ValueError):
                vectors.append({"data": data.hex(), "level": name, "overflow": True})
                continue
            rows = ["".join("1" if m else "0" for m in row) for row in qr.modules]
            vector = {
                "data": data.hex(),
                "level": name,
                "version": qr.version,
                "matrix_sha256": hashlib.sha256("\n".join(rows).encode()).hexdigest(),
            }
            if qr.version <= 3:
                vector["rows"] = rows
            # best_mask_pattern rebuilds the modules, so it runs after the copy.
            vector["mask"] = qr.best_mask_pattern()
            if name == "M":
                vector["svg_sha256"] = hashlib.sha256(svg(data)).hexdigest()
            vectors.append(vector)
    vectors.append({"data": (b"9" * 7090).hex(), "level": "L", "overflow": True})
    target = pathlib.Path(__file__).with_name("python_vectors.json")
    target.write_text(json.dumps({"qrcode": qrcode.__version__ if hasattr(qrcode, "__version__") else "8.2", "vectors": vectors}, indent=0, sort_keys=True) + "\n")
    print(f"{len(vectors)} vectors", file=sys.stderr)


if __name__ == "__main__":
    main()
