"""Fail CI when first-party license declarations drift from Apache-2.0.

Historical MIT notices and independently licensed vendor files are intentional.
This is a consistency check, not a copyright or legal-compliance audit.
"""
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
FILES = {
    "README.md": [r"Apache License 2\.0", r"license-Apache--2\.0"],
    "CONTRIBUTING.md": [r"Apache License 2\.0"],
    "site/index.html": [r"Apache License 2\.0", r"Apache 2\.0 licensed"],
    "site/security.html": [r"Apache License 2\.0"],
    "site/impressum.html": [r"Apache License 2\.0"],
    "Dockerfile": [r"org\.opencontainers\.image\.licenses=Apache-2\.0", r"COPY config\.py start\.py LICENSE LICENSE-MIT-ORIGINAL NOTICE /app/"],
}

# SHA-256 of the complete UTF-8 text, with universal newline normalization.
# Apache: https://www.apache.org/licenses/LICENSE-2.0.txt
# MIT: the original project license, retained without changing its terms.
LICENSE_DIGESTS = {
    "LICENSE": "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
    "LICENSE-MIT-ORIGINAL": "01879c661749199143546c9f2789a8e11d2a55346501e435e798c88bff463e2a",
}


def read_text(name, errors):
    try:
        return (ROOT / name).read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        errors.append(f"{name}: missing or unreadable license input")
        return None


def main():
    errors = []
    for name, patterns in FILES.items():
        text = read_text(name, errors)
        if text is None:
            continue
        for pattern in patterns:
            if not re.search(pattern, text):
                errors.append(f"{name}: missing expected Apache license declaration: {pattern}")
        if re.search(r"MIT[- ]licensed|MIT [Ll]icense|license-MIT|licenses=MIT", text):
            errors.append(f"{name}: stale MIT project license declaration")
    for name, digest in LICENSE_DIGESTS.items():
        text = read_text(name, errors)
        if text is not None and hashlib.sha256(text.encode("utf-8")).hexdigest() != digest:
            errors.append(f"{name}: license text differs from the complete retained license")
    notice = read_text("NOTICE", errors)
    if notice is not None:
        for required in ("WebSSH", "Copyright (c) 2026 H31mdall", "LICENSE-MIT-ORIGINAL", "third-party"):
            if required not in notice:
                errors.append(f"NOTICE: missing attribution or license reference: {required}")
    for name in ("package.json", "package-lock.json"):
        text = read_text(name, errors)
        if text is None:
            continue
        try:
            package = json.loads(text)
            if name == "package-lock.json":
                package = package["packages"][""]
            if package["license"] != "Apache-2.0":
                errors.append(f"{name}: expected Apache-2.0 project license")
        except (ValueError, KeyError, TypeError):
            errors.append(f"{name}: invalid or missing project license metadata")
    if errors:
        raise SystemExit("\n".join(errors))
    print("First-party Apache-2.0 declarations and retained notices are consistent.")


if __name__ == "__main__":
    main()
