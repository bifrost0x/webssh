"""Deterministic asymmetric key material for the golden data set.

OpenSSL key generation cannot be seeded, so keys are derived from the
generator's seeded stream: Ed25519 from a 32-byte seed, ECDSA from a private
scalar, RSA from two primes found with a seeded Miller-Rabin search. The keys
are synthetic test material only.
"""

import math
import random

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

RSA_PUBLIC_EXPONENT = 65537
_MILLER_RABIN_ROUNDS = 40
_SMALL_PRIMES = tuple(
    n for n in range(3, 2000, 2)
    if all(n % d for d in range(3, int(n ** 0.5) + 1, 2))
)

CURVES = {
    'nistp256': ec.SECP256R1,
    'nistp384': ec.SECP384R1,
    'nistp521': ec.SECP521R1,
}


def _probable_prime(candidate, rng):
    if candidate < 2:
        return False
    for small in _SMALL_PRIMES:
        if candidate % small == 0:
            return candidate == small
    d, r = candidate - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(_MILLER_RABIN_ROUNDS):
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


def _prime(bits, rng):
    while True:
        candidate = rng.getrandbits(bits) | (3 << (bits - 2)) | 1
        if (
            math.gcd(candidate - 1, RSA_PUBLIC_EXPONENT) == 1
            and _probable_prime(candidate, rng)
        ):
            return candidate


def rsa_key(stream, bits=2048):
    """RSA key whose primes come from a stream-seeded search."""
    rng = random.Random(stream.read(32))
    while True:
        p = _prime(bits // 2, rng)
        q = _prime(bits // 2, rng)
        if p != q and (p * q).bit_length() == bits:
            break
    if p < q:
        p, q = q, p
    n = p * q
    d = pow(RSA_PUBLIC_EXPONENT, -1, (p - 1) * (q - 1))
    numbers = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=rsa.rsa_crt_dmp1(d, p),
        dmq1=rsa.rsa_crt_dmq1(d, q),
        iqmp=rsa.rsa_crt_iqmp(p, q),
        public_numbers=rsa.RSAPublicNumbers(RSA_PUBLIC_EXPONENT, n),
    )
    return numbers.private_key()


def ec_key(stream, curve_name):
    """ECDSA key from a stream-drawn scalar on one of the OpenSSH curves."""
    curve = CURVES[curve_name]()
    while True:
        scalar = int.from_bytes(stream.read((curve.key_size + 7) // 8 + 8))
        scalar %= 1 << curve.key_size
        try:
            return ec.derive_private_key(scalar, curve)
        except ValueError:
            continue


def ed25519_key(stream):
    return ed25519.Ed25519PrivateKey.from_private_bytes(stream.read(32))
