"""Tests for SSH private-key validation and encrypted storage."""

from pathlib import Path

import pytest


def create_user(app, username='key-user'):
    from app.models import User, db

    with app.app_context():
        user = User(username=username, password_hash='not-used-in-this-test')
        db.session.add(user)
        db.session.commit()
        return user.id


@pytest.mark.parametrize(
    ('fixture_name', 'expected'),
    [
        ('rsa_private_key_pem', 'RSA'),
        ('ed25519_private_key_pem', 'Ed25519'),
        ('ecdsa_private_key_pem', 'ECDSA'),
    ],
)
def test_detects_real_supported_key_types(
        request, fixture_name, expected):
    from app.key_manager import detect_key_type

    key_content = request.getfixturevalue(fixture_name)
    assert detect_key_type(key_content) == expected


def test_dsa_is_not_reported_as_supported(dsa_private_key_pem):
    from app.key_manager import detect_key_type

    assert detect_key_type(dsa_private_key_pem) is None


@pytest.mark.parametrize(
    'content',
    [
        'not a key at all',
        '',
        '   ',
        (
            '-----BEGIN RSA PRIVATE KEY-----\n'
            'invalid\n'
            '-----END RSA PRIVATE KEY-----'
        ),
        (
            '-----BEGIN OPENSSH PRIVATE KEY-----\n'
            'invalid\n'
            '-----END OPENSSH PRIVATE KEY-----'
        ),
    ],
)
def test_malformed_or_empty_content_is_not_detected(content):
    from app.key_manager import detect_key_type

    assert detect_key_type(content) is None


@pytest.mark.parametrize(
    ('fixture_name', 'expected_type'),
    [
        ('rsa_private_key_pem', 'RSA'),
        ('ed25519_private_key_pem', 'Ed25519'),
        ('ecdsa_private_key_pem', 'ECDSA'),
    ],
)
def test_save_key_validates_encrypts_and_records_supported_key(
        app, request, fixture_name, expected_type):
    from app import key_encryption, key_manager

    user_id = create_user(app, username=f'user-{expected_type.lower()}')
    key_content = request.getfixturevalue(fixture_name)

    with app.app_context():
        key_meta, error = key_manager.save_key(
            user_id,
            f'{expected_type} test key',
            key_content,
        )

        assert error is None
        assert key_meta['key_type'] == expected_type
        assert key_meta['passphrase_required'] is False
        key_path = Path(key_manager.get_key_path(user_id, key_meta['id']))
        raw = key_path.read_bytes()
        assert key_encryption.is_encrypted(raw) is True
        assert key_content.encode('utf-8') not in raw
        loaded_content, load_error = key_manager.read_key_content(
            user_id,
            key_meta['id'],
        )
        assert load_error is None
        assert loaded_content == key_content


@pytest.mark.parametrize(
    ('fixture_name', 'expected_error'),
    [
        (
            'dsa_private_key_pem',
            'DSA private keys are not supported; use Ed25519, ECDSA, or RSA',
        ),
        ('encrypted_rsa_private_key_pem', 'SSH key passphrase required'),
    ],
)
def test_save_key_rejects_unsupported_key_without_writing(
        app, request, fixture_name, expected_error):
    from app import key_manager

    user_id = create_user(app, username=f'rejected-{fixture_name}')
    key_content = request.getfixturevalue(fixture_name)

    with app.app_context():
        keys_dir = key_manager.get_user_keys_dir(user_id)
        before = set(keys_dir.iterdir())

        key_meta, error = key_manager.save_key(
            user_id,
            'rejected key',
            key_content,
        )

        assert key_meta is None
        assert error == expected_error
        assert set(keys_dir.iterdir()) == before
        assert key_manager.load_keys(user_id) == []


@pytest.mark.parametrize(
    ('fixture_name', 'expected_type'),
    [
        ('encrypted_rsa_private_key_pem', 'RSA'),
        ('encrypted_ed25519_private_key_pem', 'Ed25519'),
        ('encrypted_ecdsa_private_key_pem', 'ECDSA'),
    ],
)
def test_save_encrypted_key_records_requirement_without_storing_passphrase(
        app, request, fixture_name, expected_type):
    from app import key_encryption, key_manager

    user_id = create_user(app, username=f'encrypted-{expected_type.lower()}')
    key_content = request.getfixturevalue(fixture_name)
    passphrase = 'test-passphrase'

    with app.app_context():
        key_meta, error = key_manager.save_key(
            user_id,
            f'{expected_type} encrypted key',
            key_content,
            key_passphrase=passphrase,
        )

        assert error is None
        assert key_meta['key_type'] == expected_type
        assert key_meta['passphrase_required'] is True
        assert passphrase not in repr(key_meta)

        key_path = Path(key_manager.get_key_path(user_id, key_meta['id']))
        raw = key_path.read_bytes()
        assert key_encryption.is_encrypted(raw) is True
        assert passphrase.encode() not in raw

        keys_file = key_manager.get_user_keys_file(user_id)
        assert passphrase not in keys_file.read_text(encoding='utf-8')


def test_save_encrypted_key_rejects_wrong_passphrase_without_writing(
        app, encrypted_rsa_private_key_pem):
    from app import key_manager

    user_id = create_user(app, username='wrong-passphrase')

    with app.app_context():
        keys_dir = key_manager.get_user_keys_dir(user_id)
        before = set(keys_dir.iterdir())
        secret = 'wrong-passphrase-value'

        key_meta, error = key_manager.save_key(
            user_id,
            'encrypted key',
            encrypted_rsa_private_key_pem,
            key_passphrase=secret,
        )

        assert key_meta is None
        assert error == 'Invalid SSH key passphrase'
        assert secret not in error
        assert set(keys_dir.iterdir()) == before


def test_load_keys_defaults_legacy_metadata_to_no_passphrase(app):
    from app import key_manager

    user_id = create_user(app, username='legacy-key-metadata')

    with app.app_context():
        key_manager.save_keys(user_id, [{
            'id': 'legacy-key',
            'name': 'Legacy key',
            'filename': 'legacy.pem',
            'key_type': 'RSA',
            'encrypted': True,
        }])

        assert key_manager.load_keys(user_id)[0]['passphrase_required'] is False


def test_save_key_rejects_malformed_pem_without_writing(app):
    from app import key_manager

    user_id = create_user(app, username='malformed-key-user')
    key_content = (
        '-----BEGIN RSA PRIVATE KEY-----\n'
        'private-material-marker\n'
        '-----END RSA PRIVATE KEY-----'
    )

    with app.app_context():
        keys_dir = key_manager.get_user_keys_dir(user_id)
        before = set(keys_dir.iterdir())

        key_meta, error = key_manager.save_key(
            user_id,
            'malformed key',
            key_content,
        )

        assert key_meta is None
        assert error == 'Unsupported or invalid private key format'
        assert 'private-material-marker' not in error
        assert set(keys_dir.iterdir()) == before
        assert key_manager.load_keys(user_id) == []
