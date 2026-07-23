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


def test_load_key_summaries_marks_missing_key_file_unusable(
        app, rsa_private_key_pem):
    from app import key_manager

    user_id = create_user(app, username='key-summary-user')

    with app.app_context():
        key_meta, error = key_manager.save_key(
            user_id,
            'summary key',
            rsa_private_key_pem,
        )
        assert error is None
        assert key_manager.load_key_summaries(user_id)[0]['usable'] is True

        Path(key_manager.get_key_path(user_id, key_meta['id'])).unlink()

        summaries = key_manager.load_key_summaries(user_id)
        assert summaries[0]['id'] == key_meta['id']
        assert summaries[0]['usable'] is False
        assert 'usable' not in key_manager.load_keys(user_id)[0]


def test_load_key_summaries_derives_user_key_once(
        app, rsa_private_key_pem, monkeypatch):
    from app import key_encryption, key_manager

    user_id = create_user(app, username='key-summary-derivation-user')

    with app.app_context():
        for name in ('first key', 'second key'):
            _, error = key_manager.save_key(user_id, name, rsa_private_key_pem)
            assert error is None

        original = key_encryption.get_user_fernet
        calls = []

        def counting_get_user_fernet(value):
            calls.append(value)
            return original(value)

        monkeypatch.setattr(
            key_encryption,
            'get_user_fernet',
            counting_get_user_fernet,
        )

        summaries = key_manager.load_key_summaries(user_id)

        assert [summary['usable'] for summary in summaries] == [True, True]
        assert calls == [str(user_id)]


@pytest.mark.parametrize(
    ('fixture_name', 'expected_error'),
    [
        (
            'dsa_private_key_pem',
            'DSA private keys are not supported; use Ed25519, ECDSA, or RSA',
        ),
        (
            'encrypted_rsa_private_key_pem',
            'Passphrase-encrypted private keys are not supported',
        ),
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
