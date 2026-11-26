"""Minimal software WebAuthn authenticator (attestation format "none").

Builds the browser-side JSON that the application hands to py_webauthn:
registration responses with a COSE public key and authentication assertions
signed over ``authenticatorData || SHA-256(clientDataJSON)`` (W3C WebAuthn
Level 3, sections 6.1, 6.5.1 and 7.2). ES256 signatures use RFC 6979
deterministic nonces so assertion vectors are reproducible.
"""

import base64
import hashlib
import json

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_BE = 0x08
FLAG_BS = 0x10
FLAG_AT = 0x40

COSE_ALGORITHMS = {'ES256': -7, 'EdDSA': -8, 'RS256': -257}


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def cose_public_key(private_key):
    """COSE_Key map (RFC 9053 / RFC 8230) for the credential public key."""
    public = private_key.public_key()
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        numbers = public.public_numbers()
        return {1: 2, 3: -7, -1: 1,
                -2: numbers.x.to_bytes(32, 'big'),
                -3: numbers.y.to_bytes(32, 'big')}
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        from cryptography.hazmat.primitives import serialization
        raw = public.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return {1: 1, 3: -8, -1: 6, -2: raw}
    if isinstance(private_key, rsa.RSAPrivateKey):
        numbers = public.public_numbers()
        n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, 'big')
        e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, 'big')
        return {1: 3, 3: -257, -1: n, -2: e}
    raise TypeError('unsupported credential key type')


def sign(private_key, message):
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return private_key.sign(
            message, ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
        )
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return private_key.sign(message)
    if isinstance(private_key, rsa.RSAPrivateKey):
        return private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    raise TypeError('unsupported credential key type')


def client_data(ceremony, challenge, origin):
    return json.dumps({
        'type': ceremony,
        'challenge': b64url(challenge),
        'origin': origin,
        'crossOrigin': False,
    }, separators=(',', ':')).encode('utf-8')


class SoftwareCredential:
    def __init__(self, private_key, credential_id, *, rp_id, origin,
                 backup_eligible=False, backup_state=False, aaguid=bytes(16)):
        self.private_key = private_key
        self.credential_id = credential_id
        self.rp_id = rp_id
        self.origin = origin
        self.aaguid = aaguid
        self.flags = FLAG_UP | FLAG_UV
        if backup_eligible:
            self.flags |= FLAG_BE
        if backup_state:
            self.flags |= FLAG_BS

    def _auth_data(self, sign_count, attested):
        rp_hash = hashlib.sha256(self.rp_id.encode('utf-8')).digest()
        flags = self.flags | (FLAG_AT if attested else 0)
        data = rp_hash + bytes([flags]) + int(sign_count).to_bytes(4, 'big')
        if attested:
            data += (
                self.aaguid
                + len(self.credential_id).to_bytes(2, 'big')
                + self.credential_id
                + cbor2.dumps(cose_public_key(self.private_key))
            )
        return data

    def registration(self, challenge, sign_count, transports):
        """PublicKeyCredential JSON returned by navigator.credentials.create."""
        auth_data = self._auth_data(sign_count, attested=True)
        attestation = cbor2.dumps({'fmt': 'none', 'attStmt': {},
                                   'authData': auth_data})
        encoded_id = b64url(self.credential_id)
        return {
            'id': encoded_id,
            'rawId': encoded_id,
            'type': 'public-key',
            'authenticatorAttachment': 'platform',
            'clientExtensionResults': {},
            'response': {
                'clientDataJSON': b64url(
                    client_data('webauthn.create', challenge, self.origin)
                ),
                'attestationObject': b64url(attestation),
                'transports': list(transports),
            },
        }

    def assertion(self, challenge, sign_count, user_handle):
        """PublicKeyCredential JSON returned by navigator.credentials.get."""
        auth_data = self._auth_data(sign_count, attested=False)
        client = client_data('webauthn.get', challenge, self.origin)
        signature = sign(
            self.private_key, auth_data + hashlib.sha256(client).digest()
        )
        encoded_id = b64url(self.credential_id)
        return {
            'id': encoded_id,
            'rawId': encoded_id,
            'type': 'public-key',
            'authenticatorAttachment': 'platform',
            'clientExtensionResults': {},
            'response': {
                'clientDataJSON': b64url(client),
                'authenticatorData': b64url(auth_data),
                'signature': b64url(signature),
                'userHandle': b64url(user_handle),
            },
        }
