from pathlib import Path

from cryptography.fernet import Fernet
import pytest

from app.backup_manager import verify_backup
from app.key_encryption import _derive_key
from app.secret_rotation import SecretRotationError, rotate_secret


def _encrypt(secret, user_id, plaintext):
    return Fernet(_derive_key(secret, str(user_id))).encrypt(plaintext)


def _rotation_data(tmp_path):
    old_secret = 'old-secret-for-rotation'
    new_secret = 'new-secret-for-rotation'
    data_dir = tmp_path / 'data'
    data_dir.mkdir()
    (data_dir / 'secret_key').write_text(old_secret + '\n', encoding='utf-8')
    plaintexts = {
        'users/user_1/keys/first.pem': b'first private key',
        'users/user_2/keys/second.pem': b'second private key',
    }
    for relative_path, plaintext in plaintexts.items():
        path = data_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        user_id = path.parts[-3].removeprefix('user_')
        path.write_bytes(_encrypt(old_secret, user_id, plaintext))
    (data_dir / 'app.db').write_bytes(b'database')
    return data_dir, old_secret, new_secret, plaintexts


def test_rotate_secret_reencrypts_every_key_and_publishes_secret_last(tmp_path):
    data_dir, old_secret, new_secret, plaintexts = _rotation_data(tmp_path)

    report = rotate_secret(old_secret, new_secret, data_dir)

    assert report.rotated_keys == 2
    assert report.backup_path.is_file()
    verify_backup(report.backup_path)
    assert not report.backup_path.is_relative_to(data_dir)
    assert (data_dir / 'secret_key').read_text(
        encoding='utf-8'
    ) == new_secret + '\n'
    for relative_path, plaintext in plaintexts.items():
        path = data_dir / relative_path
        user_id = path.parts[-3].removeprefix('user_')
        assert Fernet(_derive_key(new_secret, user_id)).decrypt(
            path.read_bytes()
        ) == plaintext


def test_rotation_staging_failure_keeps_old_secret_and_all_ciphertexts(
    tmp_path,
    monkeypatch,
):
    from app import secret_rotation

    data_dir, old_secret, new_secret, plaintexts = _rotation_data(tmp_path)
    originals = {
        relative_path: (data_dir / relative_path).read_bytes()
        for relative_path in plaintexts
    }
    original_write = secret_rotation._write_staged_key
    calls = 0

    def fail_second_write(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError('forced second key write failure')
        return original_write(*args, **kwargs)

    monkeypatch.setattr(
        secret_rotation,
        '_write_staged_key',
        fail_second_write,
    )

    with pytest.raises(OSError, match='forced second key write failure'):
        rotate_secret(old_secret, new_secret, data_dir)

    assert (data_dir / 'secret_key').read_text(
        encoding='utf-8'
    ) == old_secret + '\n'
    for relative_path, plaintext in plaintexts.items():
        path = data_dir / relative_path
        ciphertext = path.read_bytes()
        assert ciphertext == originals[relative_path]
        user_id = path.parts[-3].removeprefix('user_')
        assert Fernet(_derive_key(old_secret, user_id)).decrypt(
            ciphertext
        ) == plaintext


def test_secret_publish_failure_rolls_back_committed_keys(
    tmp_path,
    monkeypatch,
):
    from app import secret_rotation

    data_dir, old_secret, new_secret, plaintexts = _rotation_data(tmp_path)
    originals = {
        relative_path: (data_dir / relative_path).read_bytes()
        for relative_path in plaintexts
    }
    secret_path = data_dir / 'secret_key'
    original_write = secret_rotation.atomic_write_bytes
    failed = False

    def fail_new_secret(path, payload, mode=0o600):
        nonlocal failed
        if (
            Path(path) == secret_path
            and payload == (new_secret + '\n').encode('utf-8')
            and not failed
        ):
            failed = True
            raise OSError('forced secret publish failure')
        return original_write(path, payload, mode)

    monkeypatch.setattr(
        secret_rotation,
        'atomic_write_bytes',
        fail_new_secret,
    )

    with pytest.raises(OSError, match='forced secret publish failure'):
        rotate_secret(old_secret, new_secret, data_dir)

    assert secret_path.read_text(encoding='utf-8') == old_secret + '\n'
    assert {
        relative_path: (data_dir / relative_path).read_bytes()
        for relative_path in plaintexts
    } == originals


def test_rotation_attempts_secret_rollback_even_if_key_rollback_fails(
    tmp_path,
    monkeypatch,
):
    from app import secret_rotation

    data_dir, old_secret, new_secret, _ = _rotation_data(tmp_path)
    secret_path = data_dir / 'secret_key'
    original_write = secret_rotation.atomic_write_bytes
    new_secret_failed = False
    key_rollback_failed = False
    old_secret_restore_attempted = False

    def fail_publish_and_first_key_rollback(path, payload, mode=0o600):
        nonlocal new_secret_failed
        nonlocal key_rollback_failed
        nonlocal old_secret_restore_attempted
        path = Path(path)
        if (
            path == secret_path
            and payload == (new_secret + '\n').encode('utf-8')
            and not new_secret_failed
        ):
            new_secret_failed = True
            raise OSError('forced secret publish failure')
        if (
            new_secret_failed
            and path.suffix == '.pem'
            and not key_rollback_failed
        ):
            key_rollback_failed = True
            raise OSError('forced key rollback failure')
        if (
            path == secret_path
            and payload == (old_secret + '\n').encode('utf-8')
        ):
            old_secret_restore_attempted = True
        return original_write(path, payload, mode)

    monkeypatch.setattr(
        secret_rotation,
        'atomic_write_bytes',
        fail_publish_and_first_key_rollback,
    )

    with pytest.raises(RuntimeError, match='rollback failed'):
        rotate_secret(old_secret, new_secret, data_dir)

    assert old_secret_restore_attempted is True


@pytest.mark.parametrize('persisted_secret', [None, 'different-secret'])
def test_rotation_rejects_missing_or_mismatched_persisted_secret(
    tmp_path,
    persisted_secret,
):
    data_dir = tmp_path / 'data'
    data_dir.mkdir()
    if persisted_secret is not None:
        (data_dir / 'secret_key').write_text(
            persisted_secret + '\n',
            encoding='utf-8',
        )

    with pytest.raises(SecretRotationError, match='persisted'):
        rotate_secret('expected-secret', 'new-secret', data_dir)

    assert list(tmp_path.glob('data-pre-rotation-*.zip')) == []


def test_rotation_rejects_invalid_new_secret_before_backup(tmp_path):
    data_dir, old_secret, _, _ = _rotation_data(tmp_path)

    with pytest.raises(SecretRotationError, match='new secret'):
        rotate_secret(old_secret, old_secret, data_dir)

    assert list(tmp_path.glob('data-pre-rotation-*.zip')) == []


def test_rotation_rejects_symlinked_data_directory(tmp_path):
    data_dir, old_secret, new_secret, _ = _rotation_data(tmp_path)
    linked_data_dir = tmp_path / 'linked-data'
    try:
        linked_data_dir.symlink_to(data_dir, target_is_directory=True)
    except OSError:
        pytest.skip('directory symlinks are unavailable in this environment')

    with pytest.raises(SecretRotationError, match='real directory'):
        rotate_secret(old_secret, new_secret, linked_data_dir)

    assert (data_dir / 'secret_key').read_text(
        encoding='utf-8'
    ) == old_secret + '\n'


def test_rotate_secret_cli_requires_offline_ack(app):
    import config

    data_dir = Path(config.DATA_DIR)
    (data_dir / 'secret_key').write_text(
        config.SECRET_KEY + '\n',
        encoding='utf-8',
    )
    before = (data_dir / 'secret_key').read_bytes()

    result = app.test_cli_runner().invoke(args=['rotate-secret-key'])

    assert result.exit_code != 0
    assert 'confirm-offline' in result.output
    assert (data_dir / 'secret_key').read_bytes() == before


def test_rotate_secret_cli_generates_and_persists_new_secret(app):
    import config

    data_dir = Path(config.DATA_DIR)
    old_secret = config.SECRET_KEY
    (data_dir / 'secret_key').write_text(
        old_secret + '\n',
        encoding='utf-8',
    )

    result = app.test_cli_runner().invoke(
        args=['rotate-secret-key', '--confirm-offline'],
    )

    assert result.exit_code == 0
    new_secret = (data_dir / 'secret_key').read_text(
        encoding='utf-8',
    ).rstrip('\n')
    assert new_secret
    assert new_secret != old_secret
    assert 'restart' in result.output.lower()
    assert len(list(data_dir.parent.glob(
        f'{data_dir.name}-pre-rotation-*.zip'
    ))) == 1
