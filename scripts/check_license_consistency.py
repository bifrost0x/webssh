"""Fail CI when first-party license declarations drift from Apache-2.0.

Historical MIT notices and independently licensed vendor files are intentional.
This is a consistency check, not a copyright or legal-compliance audit.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
FILES = {
    "README.md": [r"Apache License 2\\.0", r"license-Apache--2\\.0"],
    "CONTRIBUTING.md": [r"Apache License 2\\.0"],
    "site/index.html": [r"Apache License 2\\.0", r"Apache 2\\.0 licensed"],
    "site/security.html": [r"Apache License 2\\.0"],
    "site/impressum.html": [r"Apache License 2\\.0"],
    "Dockerfile": [r"org\\.opencontainers\\.image\\.licenses=Apache-2\\.0", r"COPY config\\.py start\\.py LICENSE LICENSE-MIT-ORIGINAL NOTICE /app/"],
}


def main():
    errors = []
    for name, patterns in FILES.items():
        text = (ROOT / name).read_text(encoding="utf-8")
        for pattern in patterns:
            if not re.search(pattern, text):
                errors.append(f"{name}: missing expected Apache license declaration: {pattern}")
        if re.search(r"MIT[- ]licensed|MIT [Ll]icense|license-MIT|licenses=MIT", text):
            errors.append(f"{name}: stale MIT project license declaration")
    for name in ("LICENSE", "LICENSE-MIT-ORIGINAL", "NOTICE"):
        if not (ROOT / name).is_file():
            errors.append(f"{name}: missing legal file")
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    if "Apache License" not in license_text or "Version 2.0, January 2004" not in license_text:
        errors.append("LICENSE: expected Apache License 2.0 text")
    original = (ROOT / "LICENSE-MIT-ORIGINAL").read_text(encoding="utf-8")
    if "MIT License" not in original or "Copyright (c) 2026 H31mdall" not in original:
        errors.append("LICENSE-MIT-ORIGINAL: missing original copyright notice")
    if errors:
        raise SystemExit("\\n".join(errors))
    print("First-party Apache-2.0 declarations and retained notices are consistent.")


if __name__ == "__main__":
    main()
