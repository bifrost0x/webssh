"""Tests for SSH private-key validation and encrypted storage."""

from pathlib import Path

import pytest

from app.storage_errors import StorageCorruptionError


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


def test_legacy_migration_failure_is_not_returned_as_key_content(
        app, rsa_private_key_pem, monkeypatch):
    from app import key_encryption, key_manager

    user_id = create_user(app, username='legacy-migration-failure')
    secret_error = 'sentinel-private-migration-error'
    logged = []

    with app.app_context():
        key_meta, error = key_manager.save_key(
            user_id,
            'legacy key',
            rsa_private_key_pem,
        )
        assert error is None
        key_path = Path(key_manager.get_key_path(user_id, key_meta['id']))
        original = rsa_private_key_pem.encode('utf-8')
        key_path.write_bytes(original)

        monkeypatch.setattr(
            key_encryption,
            'atomic_write_bytes',
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                OSError(secret_error)
            ),
        )
        monkeypatch.setattr(
            key_manager,
            'log_error',
            lambda message, **fields: logged.append((message, fields)),
        )

        content, read_error = key_manager.read_key_content(
            user_id, key_meta['id']
        )

        assert content is None
        assert read_error == 'Failed to read key'
        assert key_path.read_bytes() == original
        assert {
            path.name for path in key_path.parent.iterdir()
        } == {'keys.json', key_path.name}
        assert logged == [(
            'Error reading key content',
            {
                'user_id': user_id,
                'key_id': key_meta['id'],
                'exception_type': 'OSError',
            },
        )]
        assert secret_error not in repr(logged)


def test_key_read_rejects_symlink_target_outside_user_keys_directory(
        app, rsa_private_key_pem, tmp_path):
    from app import key_manager

    user_id = create_user(app, username='external-key-symlink')
    original = rsa_private_key_pem.encode('utf-8')

    with app.app_context():
        key_meta, error = key_manager.save_key(
            user_id,
            'External symlink',
            rsa_private_key_pem,
        )
        assert error is None
        key_path = Path(key_manager.get_key_path(user_id, key_meta['id']))
        key_path.unlink()
        outside = tmp_path / 'outside-private-key.pem'
        outside.write_bytes(original)
        try:
            key_path.symlink_to(outside)
        except OSError as exc:
            pytest.skip(
                f'symlink creation unavailable: {type(exc).__name__}'
            )

        content, read_error = key_manager.read_key_content(
            user_id, key_meta['id']
        )

        assert content is None
        assert read_error == 'Failed to read key'
        assert key_path.is_symlink()
        assert outside.read_bytes() == original


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


def test_save_key_preserves_corrupt_metadata_store(app, rsa_private_key_pem):
    from app import key_manager

    user_id = create_user(app, username='corrupt-key-metadata')
    corrupt = b'{"keys": ['
    with app.app_context():
        metadata_path = key_manager.get_user_keys_file(user_id)
        metadata_path.write_bytes(corrupt)
        before_files = set(metadata_path.parent.iterdir())

        with pytest.raises(StorageCorruptionError) as exc_info:
            key_manager.save_key(user_id, 'must-not-write', rsa_private_key_pem)

        assert exc_info.value.path == metadata_path
        assert metadata_path.read_bytes() == corrupt
        assert set(metadata_path.parent.iterdir()) == before_files


def test_save_key_removes_pem_before_propagating_typed_metadata_error(
    app, rsa_private_key_pem, monkeypatch
):
    from app import key_manager
    from app.storage_errors import StorageCorruptionError

    user_id = create_user(app, username='typed-metadata-save-error')
    with app.app_context():
        metadata_path = key_manager.get_user_keys_file(user_id)
        monkeypatch.setattr(
            key_manager,
            'save_keys',
            lambda *_args: (_ for _ in ()).throw(
                StorageCorruptionError(metadata_path, 'validation failed')
            ),
        )

        with pytest.raises(StorageCorruptionError):
            key_manager.save_key(
                user_id, 'must-clean-up', rsa_private_key_pem
            )

        assert list(metadata_path.parent.glob('*.pem')) == []


def test_save_key_removes_pem_and_hides_untyped_metadata_exception(
    app, rsa_private_key_pem, monkeypatch
):
    from app import key_manager

    user_id = create_user(app, username='untyped-metadata-save-error')
    secret_marker = 'private-metadata-save-marker'
    with app.app_context():
        keys_dir = key_manager.get_user_keys_dir(user_id)
        monkeypatch.setattr(
            key_manager,
            'save_keys',
            lambda *_args: (_ for _ in ()).throw(RuntimeError(secret_marker)),
        )

        key, error = key_manager.save_key(
            user_id, 'must-clean-up', rsa_private_key_pem
        )

        assert key is None
        assert error == 'Failed to save key metadata'
        assert secret_marker not in error
        assert list(keys_dir.glob('*.pem')) == []


def test_save_key_false_metadata_result_removes_pem(
    app, rsa_private_key_pem, monkeypatch
):
    from app import key_manager

    user_id = create_user(app, username='false-metadata-save')
    with app.app_context():
        keys_dir = key_manager.get_user_keys_dir(user_id)
        monkeypatch.setattr(key_manager, 'save_keys', lambda *_args: False)

        key, error = key_manager.save_key(
            user_id, 'must-clean-up', rsa_private_key_pem
        )

        assert key is None
        assert error == 'Failed to save key metadata'
        assert list(keys_dir.glob('*.pem')) == []


def test_save_key_cleanup_error_keeps_safe_api_and_log(
    app, rsa_private_key_pem, monkeypatch
):
    from app import key_manager

    user_id = create_user(app, username='metadata-cleanup-error')
    secret_marker = 'private-cleanup-marker'
    warnings = []
    with app.app_context():
        keys_dir = key_manager.get_user_keys_dir(user_id)
        monkeypatch.setattr(key_manager, 'save_keys', lambda *_args: False)
        original_unlink = Path.unlink

        def fail_pem_unlink(path, *args, **kwargs):
            if path.suffix == '.pem':
                raise OSError(secret_marker)
            return original_unlink(path, *args, **kwargs)

        monkeypatch.setattr(Path, 'unlink', fail_pem_unlink)
        monkeypatch.setattr(
            key_manager,
            'log_warning',
            lambda message, **fields: warnings.append((message, fields)),
        )

        key, error = key_manager.save_key(
            user_id, 'cleanup-fails', rsa_private_key_pem
        )

        assert key is None
        assert error == 'Failed to save key metadata'
        assert secret_marker not in error
        assert warnings == [(
            'Failed to remove key after metadata save failure',
            {
                'user_id': user_id,
                'key_id': next(keys_dir.glob('*.pem')).stem,
                'cleanup_error': 'OSError',
            },
        )]
        assert secret_marker not in repr(warnings)


def test_save_key_non_os_cleanup_error_is_safe_and_does_not_mask_corruption(
    app, rsa_private_key_pem, monkeypatch
):
    from app import key_manager
    from app.storage_errors import StorageCorruptionError

    user_id = create_user(app, username='metadata-runtime-cleanup-error')
    secret_marker = 'private-runtime-cleanup-marker'
    warnings = []
    with app.app_context():
        metadata_path = key_manager.get_user_keys_file(user_id)
        monkeypatch.setattr(
            key_manager,
            'save_keys',
            lambda *_args: (_ for _ in ()).throw(
                StorageCorruptionError(metadata_path, 'validation failed')
            ),
        )
        monkeypatch.setattr(
            Path,
            'unlink',
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                RuntimeError(secret_marker)
            ),
        )
        monkeypatch.setattr(
            key_manager,
            'log_warning',
            lambda message, **fields: warnings.append((message, fields)),
        )

        with pytest.raises(StorageCorruptionError):
            key_manager.save_key(
                user_id, 'cleanup-fails', rsa_private_key_pem
            )

        assert warnings
        assert warnings[0][0] == (
            'Failed to remove key after metadata save failure'
        )
        assert warnings[0][1]['cleanup_error'] == 'RuntimeError'
        assert secret_marker not in repr(warnings)


def test_referenced_key_is_revoked_without_rewriting_profile(
    app, rsa_private_key_pem
):
    from app import key_manager, profile_manager

    user_id = create_user(app, username='referenced-key-revocation')
    with app.app_context():
        key, error = key_manager.save_key(
            user_id, 'Revocable', rsa_private_key_pem
        )
        assert error is None
        profile, error = profile_manager.upsert_profile(user_id, {
            'name': 'Production',
            'host': 'target.example',
            'port': 22,
            'username': 'deploy',
            'auth_type': 'key',
            'key_id': key['id'],
        })
        assert error is None

        assert key_manager.delete_key(user_id, key['id']) is True

        stored = profile_manager.get_profile(user_id, profile['id'])
        assert stored['key_id'] == key['id']
        assert key_manager.get_key(user_id, key['id']) is None
        assert key_manager.read_key_content(
            user_id, key['id']
        ) == (None, 'Key not found')
