"""TOTP, recovery codes and passkeys created through the application code."""

import json

from . import authenticator, key_material, runtime

TOTP_BINDING = 'golden-totp-enrollment-binding-0001'

# One credential per COSE algorithm the app accepts by default
# (webauthn.registration.generate_registration_options
# default_supported_pub_key_algs: EdDSA, ES256, RS256).
PASSKEYS = (
    {'name': 'Golden ES256', 'alg': 'ES256', 'sign_count': 7,
     'transports': ['internal', 'hybrid'], 'backup_eligible': False,
     'backup_state': False},
    {'name': 'Golden RS256', 'alg': 'RS256', 'sign_count': 41,
     'transports': ['usb'], 'backup_eligible': False, 'backup_state': False},
    # Synced passkeys report a zero counter and the backup flags.
    {'name': 'Synced passkey ✓ 日本', 'alg': 'EdDSA', 'sign_count': 0,
     'transports': ['internal'], 'backup_eligible': True,
     'backup_state': True},
    # Registered, then removed by its owner (edge_cases.delete_passkey).
    {'name': 'Golden removed', 'alg': 'ES256', 'sign_count': 3,
     'transports': [], 'backup_eligible': True, 'backup_state': False},
)


def enroll_totp(user, clock):
    """begin_totp_enrollment + activate_totp_enrollment with a valid code."""
    from app.totp_service import (
        _totp_code, activate_totp_enrollment, begin_totp_enrollment,
    )

    view = begin_totp_enrollment(user.id, TOTP_BINDING, label='Golden phone')
    clock.advance(seconds=20)
    step = int(clock.now.timestamp()) // 30
    code = _totp_code(view.secret, step)
    authenticator_row = activate_totp_enrollment(
        view.token, code, TOTP_BINDING, now=clock.now,
    )
    return {
        'secret_base32': view.secret,
        'provisioning_uri': view.provisioning_uri,
        'activation_step': step,
        'activation_code': code,
        'recovery_codes': list(authenticator_row.recovery_codes),
        'authenticator_id': authenticator_row.id,
    }


def pending_totp_enrollment(user):
    """An unconfirmed enrollment row, as left by an abandoned setup."""
    from app.totp_service import begin_totp_enrollment
    view = begin_totp_enrollment(user.id, TOTP_BINDING + '-pending',
                                 label='Abandoned setup')
    return {'secret_base32': view.secret, 'expires_at': view.expires_at}


def _credential_key(stream, alg):
    if alg == 'ES256':
        return key_material.ec_key(stream, 'nistp256')
    if alg == 'RS256':
        return key_material.rsa_key(stream, 2048)
    return key_material.ed25519_key(stream)


def register_passkeys(user, stream, clock):
    """Registration ceremony as in app/webauthn_routes.py verify_registration."""
    import config
    from webauthn import generate_registration_options, verify_registration_response
    from app.models import WebAuthnCredential, db
    from app.webauthn_service import consume_challenge, create_challenge

    credentials = []
    for spec in PASSKEYS:
        clock.advance(seconds=5)
        private_key = _credential_key(stream, spec['alg'])
        software = authenticator.SoftwareCredential(
            private_key, stream.read(32), rp_id=config.WEBAUTHN_RP_ID,
            origin=config.WEBAUTHN_ORIGIN,
            backup_eligible=spec['backup_eligible'],
            backup_state=spec['backup_state'],
        )
        options = generate_registration_options(
            rp_id=config.WEBAUTHN_RP_ID,
            rp_name=config.WEBAUTHN_RP_NAME,
            user_id=str(user.id).encode('ascii'),
            user_name=user.username,
            user_display_name=user.username,
        )
        binding = 'golden-registration-binding-' + spec['alg']
        create_challenge(user_id=user.id, purpose='register',
                         session_binding=binding,
                         challenge=bytes(options.challenge))
        challenge = consume_challenge(user_id=user.id, purpose='register',
                                      session_binding=binding)
        response = software.registration(challenge, spec['sign_count'],
                                         spec['transports'])
        verified = verify_registration_response(
            credential=response,
            expected_challenge=challenge,
            expected_rp_id=config.WEBAUTHN_RP_ID,
            expected_origin=config.WEBAUTHN_ORIGIN,
            require_user_verification=True,
        )
        row = WebAuthnCredential(
            user_id=user.id,
            credential_id=bytes(verified.credential_id),
            public_key=bytes(verified.credential_public_key),
            sign_count=int(verified.sign_count),
            transports=json.dumps(response['response']['transports']),
            name=spec['name'],
        )
        db.session.add(row)
        db.session.commit()
        credentials.append((spec, software, row.id, response))
    return credentials


def enable_passkey_mfa(user):
    """app/webauthn_routes.py enable_passkey_mfa without the step-up gate."""
    from app.models import db
    from app.recovery_service import _replace_codes_uncommitted
    codes = _replace_codes_uncommitted(user.id, count=10)
    user.mfa_enabled = True
    db.session.commit()
    return codes


def assertion_vectors(user, credentials, stream):
    """One valid assertion per credential, not applied to the fixture."""
    vectors = []
    for spec, software, row_id, registration in credentials:
        challenge = stream.read(32)
        next_count = spec['sign_count'] + 1 if spec['sign_count'] else 0
        assertion = software.assertion(
            challenge, next_count, str(user.id).encode('ascii'),
        )
        vectors.append({
            'credential_row_id': row_id,
            'name': spec['name'],
            'cose_alg': authenticator.COSE_ALGORITHMS[spec['alg']],
            'challenge_b64url': authenticator.b64url(challenge),
            'expected_rp_id': runtime.RP_ID,
            'expected_origin': runtime.ORIGIN,
            'stored_sign_count': spec['sign_count'],
            'assertion_sign_count': next_count,
            'flags': {
                'UP': True, 'UV': True,
                'BE': spec['backup_eligible'], 'BS': spec['backup_state'],
            },
            'registration_response': registration,
            'assertion_response': assertion,
        })
    return vectors
