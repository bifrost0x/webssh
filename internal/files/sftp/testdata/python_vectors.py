"""Record the SFTP metadata decisions of the Python release as test vectors.

Usage (from the repository root, with the project virtual environment):

    SECRET_KEY=$(openssl rand -hex 32) DATA_DIR=$(mktemp -d) \
        .venv/bin/python -I internal/files/sftp/testdata/python_vectors.py . \
        internal/files/sftp/testdata/python_vectors.json.gz

app/sftp_metadata.py, app/paramiko_channels.py and app/sftp_handler.py are
loaded unchanged from the given checkout with the default configuration.
The packets are generated from a fixed seed: well-formed attribute blocks,
NAME replies and VERSION replies, and mutations of them (truncation,
unknown flags, oversized strings, too many extensions, trailing bytes).
"""

import base64
import gzip
import io
import json
import pathlib
import random
import struct
import sys

root = pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root))

import config  # noqa: E402
from paramiko.message import Message  # noqa: E402
from paramiko.sftp import CMD_ATTRS, CMD_NAME, CMD_VERSION  # noqa: E402
from app import paramiko_channels, session_directory, sftp_handler, sftp_metadata  # noqa: E402

rng = random.Random(20261127)


def u32(v):
    return struct.pack('>I', v & 0xFFFFFFFF)


def sstr(b):
    return u32(len(b)) + b


def rand_bytes(n):
    return bytes(rng.randrange(0x20, 0x7F) for _ in range(n))


def attrs_block():
    flags = 0
    out = b''
    for flag in (1, 2, 4, 8):
        if rng.random() < 0.6:
            flags |= flag
    if rng.random() < 0.3:
        flags |= 0x80000000
    if rng.random() < 0.05:
        flags |= 1 << rng.randrange(4, 31)
    if flags & 1:
        out += struct.pack('>Q', rng.randrange(1 << 40))
    if flags & 2:
        out += u32(rng.randrange(65536)) + u32(rng.randrange(65536))
    if flags & 4:
        out += u32(rng.choice([0o100644, 0o040755, 0o120777, 0o104755]))
    if flags & 8:
        out += u32(rng.randrange(1 << 31)) + u32(rng.randrange(1 << 31))
    if flags & 0x80000000:
        count = rng.choice([0, 1, 2, 16, 17, 40])
        out += u32(count)
        big = count <= 2 and rng.random() < 0.3
        for _ in range(min(count, 20)):
            size = rng.choice([4096, 4097, 33000]) if big and rng.random() < 0.5 else rng.choice([0, 3, 100])
            out += sstr(rand_bytes(size)) + sstr(rand_bytes(rng.choice([0, 5, 33000]) if big else 5))
    return u32(flags) + out


def mutate(body):
    roll = rng.random()
    if roll < 0.15 and body:
        return body[:rng.randrange(len(body))]
    if roll < 0.25:
        return body + rand_bytes(rng.randrange(1, 5))
    if roll < 0.3 and len(body) >= 4:
        return u32(rng.randrange(1 << 32)) + body[4:]
    return body


def name_reply():
    count = rng.choice([0, 1, 2, 5])
    out = u32(count if rng.random() > 0.05 else count + 3)
    for _ in range(count):
        name = rand_bytes(rng.choice([1, 8, 255, 255, 255, 255, 4096, 4097]) if rng.random() < 0.2 else rng.randrange(1, 40))
        long = rand_bytes(rng.choice([0, 40, 5000]) if rng.random() < 0.1 else 40)
        out += sstr(name) + sstr(long) + attrs_block()
    return out


def python_accepts(command, body):
    try:
        sftp_metadata.validate_metadata_packet(command, u32(7) + body)
    except Exception:
        return False
    if command == CMD_ATTRS:
        message = Message(body)
        try:
            sftp_handler._bounded_sftp_attributes(message, '', '')
        except Exception:
            return False
        return not message.get_remainder()
    return True


class VersionProbe(paramiko_channels.BoundedSFTPClient):
    def __init__(self, data):
        self._data = data

    def _send_packet(self, *_args):
        pass

    def _read_packet(self):
        return CMD_VERSION, self._data


def python_version(body):
    probe = VersionProbe(body)
    try:
        version = probe._send_version()
    except Exception:
        return None
    return {'version': version, 'extensions': probe.server_extensions}


def version_reply():
    out = u32(rng.choice([3, 3, 3, 4]))
    names = ['posix-rename@openssh.com', 'lsetstat@openssh.com', 'limits@openssh.com', 'fsync@openssh.com']
    for _ in range(rng.choice([0, 1, 3, 5, 5, 5, 65])):
        name = rng.choice(names).encode()
        data = rng.choice([b'1', b'2', b'', 'ä'.encode(), rand_bytes(257)]) if rng.random() < 0.3 else b'1'
        if rng.random() < 0.05:
            name = 'é'.encode()
        out += sstr(name) + sstr(data)
    return out


vectors = {'attrs': [], 'names': [], 'version': [], 'entry_names': [], 'directory': [], 'probe': []}
for _ in range(300):
    body = mutate(attrs_block())
    vectors['attrs'].append({'b64': base64.b64encode(body).decode(), 'accept': python_accepts(CMD_ATTRS, body)})
for _ in range(150):
    body = mutate(name_reply())
    accept = python_accepts(CMD_NAME, body)
    vectors['names'].append({
        'b64': base64.b64encode(body).decode(),
        'accept': accept,
        # The directory reader also refuses an empty NAME reply.
        'listing': accept and len(body) >= 4 and struct.unpack('>I', body[:4])[0] > 0,
    })
for _ in range(300):
    body = mutate(version_reply())
    vectors['version'].append({'b64': base64.b64encode(body).decode(), 'result': python_version(body)})
for name in ['a', '.', '..', '', 'a/b', 'a\\b', 'a\x00b', ' ', 'notes..txt', 'ä', '.hidden', 'x' * 300]:
    vectors['entry_names'].append({'name': name, 'safe': sftp_handler._is_safe_transfer_entry_name(name)})

def directory_cases():
    base = ['webssh-directory', '1234', '1', 'bash', '/home/u']
    yield base + ['']
    yield base + ['1', '']
    yield base + ['0', '']
    yield base + ['2', '']
    yield base + ['', '1234:7:p', '']
    yield base + ['1', '1234:7:c', '']
    yield base + ['1', '99:7:c', '']
    yield base + ['1', '1234:0:c', '']
    yield base + ['1', '1234:7:x', '']
    yield base + ['1', '', '']
    yield ['webssh-directory', '1234', '1', 'zsh', '/srv', '1', '1234:7:p', '']
    yield ['webssh-directory', '0', '1', 'bash', '/', '']
    yield ['webssh-directory', '007', '0', 'sh', '/tmp', '']
    yield ['webssh-directory', '-1', '1', 'bash', '/', '']
    yield ['webssh-directory', '12', '2', 'bash', '/', '']
    yield ['webssh-directory', '12', '1', 'tcsh', '/', '']
    yield ['webssh-directory', '12', '1', 'bash', 'rel', '']
    yield ['webssh-directory', '12', '1', 'bash', '/a\x01b', '']
    yield ['webssh-directory', '12', '1', 'bash', '/a\x85b', '']
    yield ['webssh-directory', '12', '1', 'bash', '/' + 'x' * 4096, '']
    yield ['webssh-directory', '12', '1', 'bash', '/' + 'x' * 4095, '']
    yield ['webssh-directory', '12', '1', 'bash', '/ä ö', '']
    yield ['other', '12', '1', 'bash', '/', '']
    yield ['webssh-directory', '12', '1', 'bash', '/']
    yield ['webssh-directory', '12', '1', 'bash', '/', 'x', 'y', 'z', '']


for parts in directory_cases():
    raw = '\0'.join(parts).encode()
    try:
        result = session_directory.parse_directory(raw)
    except (ValueError, UnicodeError):
        result = None
    vectors['directory'].append({'b64': base64.b64encode(raw).decode(), 'result': result})
vectors['directory'].append({'b64': base64.b64encode(b'webssh-directory\x0012\x001\x00bash\x00/\xff\x00').decode(), 'result': None})
for use_tmux, name in [(False, None), (True, 'webssh-abc'), (True, "it's"), (True, 'a b'), (True, '')]:
    vectors['probe'].append({
        'tmux': name if use_tmux and name else '',
        'command': session_directory.probe_command({'use_tmux': use_tmux, 'tmux_session_name': name}),
    })

with open(sys.argv[2], 'wb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', mtime=0) as packed, \
        io.TextIOWrapper(packed, encoding='utf-8') as out:
    json.dump({
        'limits': {
            'max_name': config.REMOTE_FILENAME_MAX_BYTES,
            'max_metadata': config.REMOTE_LISTING_MAX_METADATA_BYTES,
            'max_handle': config.SFTP_MAX_HANDLE_BYTES,
        },
        'vectors': vectors,
    }, out, indent=0, sort_keys=True)
    out.write('\n')
