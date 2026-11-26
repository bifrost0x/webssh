"""Raw SFTP throughput without WebSSH, as a reference for the app numbers.

Usage: python tests/baseline/reference_sftp.py HOST PORT USER PASSWORD_FILE

Uploads and downloads 200 MiB with paramiko (the library the app uses):
pipelined put, and get with and without prefetch. Prints one JSON object.
"""

import hashlib
import json
import os
import sys
import tempfile
import time

import paramiko

SIZE = 200 * 1024 * 1024
CHUNK = 65536


def main():
    host, port, user, password_file = sys.argv[1:5]
    with open(password_file, encoding='utf-8') as handle:
        password = handle.read().strip()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, int(port), user, password, look_for_keys=False, allow_agent=False)
    sftp = client.open_sftp()
    remote = '/config/reference.bin'
    result = {}
    with tempfile.TemporaryFile() as source:
        source.write(os.urandom(SIZE))
        source.seek(0)
        started = time.perf_counter()
        sftp.putfo(source, remote, file_size=SIZE)
        result['upload_pipelined_s'] = time.perf_counter() - started

    for name, prefetch in (('download_prefetch_s', True), ('download_sequential_64k_s', False)):
        digest = hashlib.sha256()
        started = time.perf_counter()
        with sftp.open(remote, 'rb') as handle:
            if prefetch:
                handle.prefetch(SIZE)
            while chunk := handle.read(CHUNK):
                digest.update(chunk)
        result[name] = time.perf_counter() - started
    sftp.remove(remote)
    client.close()
    result = {key: {'seconds': value, 'mib_per_s': SIZE / 1048576 / value} for key, value in result.items()}
    print(json.dumps(result))


if __name__ == '__main__':
    main()
