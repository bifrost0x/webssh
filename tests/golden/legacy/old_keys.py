"""Key material that early releases accepted and the current one refuses.

The initial release (2fcd38a) stored any upload whose text contained a
known PEM header: DSA keys, passphrase-protected keys and PKCS#8. Neither
OpenSSL DSA parameter generation nor PEM passphrase encryption can be seeded,
so both are built here from the seeded stream:

* DSA: a 160-bit q and a 1024-bit p = k*q + 1 from a seeded Miller-Rabin
  search, g = 2^((p-1)/q) mod p, x from the stream.
* Passphrase PEM: the traditional OpenSSL envelope ("Proc-Type: 4,ENCRYPTED",
  AES-128-CBC, key = EVP_BytesToKey(MD5, passphrase, IV[:8]), PKCS#7 padding)
  that ``openssl rsa -aes128`` writes and every OpenSSL release reads.

Only the standard library and ``cryptography`` are used, so the module runs
inside the virtual environment of an old release as well.
"""

import base64
import hashlib
import random

from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_ROUNDS = 40


def _probable_prime(candidate, rng):
    if candidate < 2 or candidate % 2 == 0:
        return candidate == 2
    for small in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if candidate % small == 0:
            return candidate == small
    d, r = candidate - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(_ROUNDS):
        x = pow(rng.randrange(2, candidate - 1), d, candidate)
        if x in (1, candidate - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, candidate)
            if x == candidate - 1:
                break
        else:
            return False
    return True


def dsa_key(stream):
    """1024/160-bit DSA key (FIPS 186-2 sizes, as ``ssh-keygen -t dsa``)."""
    rng = random.Random(stream.read(32))
    while True:
        q = rng.getrandbits(160) | (1 << 159) | 1
        if _probable_prime(q, rng):
            break
    while True:
        k = rng.getrandbits(1024 - 160) | (1 << (1024 - 161))
        p = k * q + 1
        if p.bit_length() == 1024 and _probable_prime(p, rng):
            break
    g = pow(2, (p - 1) // q, p)
    x = rng.randrange(1, q)
    parameters = dsa.DSAParameterNumbers(p, q, g)
    public = dsa.DSAPublicNumbers(pow(g, x, p), parameters)
    return dsa.DSAPrivateNumbers(x, public).private_key()


def traditional_pem(private_key):
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode('ascii')


def _evp_bytes_to_key(passphrase, salt, length):
    derived, block = b'', b''
    while len(derived) < length:
        block = hashlib.md5(block + passphrase + salt).digest()
        derived += block
    return derived[:length]


def encrypted_traditional_pem(private_key, passphrase, stream):
    """Traditional PEM with an OpenSSL passphrase envelope (AES-128-CBC)."""
    der = private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    iv = stream.read(16)
    key = _evp_bytes_to_key(passphrase.encode('utf-8'), iv[:8], 16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(der) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    body = base64.b64encode(encryptor.update(padded) + encryptor.finalize()).decode('ascii')
    label = traditional_pem(private_key).splitlines()[0][len('-----BEGIN '):-len('-----')]
    lines = [f'-----BEGIN {label}-----', 'Proc-Type: 4,ENCRYPTED',
             f'DEK-Info: AES-128-CBC,{iv.hex().upper()}', '']
    lines += [body[i:i + 64] for i in range(0, len(body), 64)]
    lines.append(f'-----END {label}-----')
    return '\n'.join(lines) + '\n'


def pkcs8_pem(private_key):
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode('ascii')


def openssh_pem(private_key):
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    ).decode('ascii')
