"""Prefer an existing official HTTPS mirror on ephemeral hosted CI runners."""

import os
from pathlib import Path
import re
import stat
import sys


MIRRORS_FILE = Path('/etc/apt/apt-mirrors.txt')
KNOWN_MIRRORS = (
    ('http://azure.archive.ubuntu.com/ubuntu/', '1', '9'),
    ('https://archive.ubuntu.com/ubuntu/', '2', '1'),
)


def prefer_official_archive(text):
    """Change only one recognized pair; keep every other byte and URL intact."""
    lines = text.splitlines(keepends=True)
    replacements = {}
    for url, old_priority, new_priority in KNOWN_MIRRORS:
        pattern = re.compile(
            r'([ \t]*' + re.escape(url) + r'[ \t]+priority:)([0-9]+)'
            r'([ \t]*(?:#[^\r\n]*)?)(\r?\n)?'
        )
        matches = [(index, match) for index, line in enumerate(lines)
                   if (match := pattern.fullmatch(line))]
        if len(matches) != 1 or matches[0][1].group(2) != old_priority:
            return text
        index, match = matches[0]
        replacements[index] = (match.group(1) + new_priority + match.group(3)
                               + (match.group(4) or ''))
    return ''.join(replacements.get(index, line) for index, line in enumerate(lines))


def main():
    if len(sys.argv) != 1:
        print('CI apt mirror setup does not accept arguments.', file=sys.stderr)
        return 2
    try:
        # Never follow even a dangling link. O_NOFOLLOW also closes the final
        # component check/open race on the Linux runners where this is invoked.
        if MIRRORS_FILE.is_symlink():
            raise OSError('Mirror configuration is a symbolic link')
        try:
            descriptor = os.open(MIRRORS_FILE, os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0))
        except FileNotFoundError:
            print('CI apt mirror priorities unchanged.')
            return 0
        with os.fdopen(descriptor, 'r+', encoding='utf-8', newline='') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise OSError('Mirror configuration is not a regular file')
            original = stream.read()
            updated = prefer_official_archive(original)
            if updated == original:
                print('CI apt mirror priorities unchanged.')
                return 0
            stream.seek(0)
            stream.write(updated)
            stream.truncate()
        print('CI apt mirror priorities updated.')
        return 0
    except (OSError, ValueError, UnicodeError):
        print('CI apt mirror priorities could not be checked.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
