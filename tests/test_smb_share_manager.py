"""Persistence contract for saved, non-secret SMB share definitions."""

import json

import pytest

from app.storage_errors import StorageCorruptionError


def _create_user(app, username='smb-share-user'):
    from app.models import User, db

    with app.app_context():
        user = User(username=username, password_hash='unused')
        db.session.add(user)
        db.session.commit()
        return user.id


def test_saved_share_persists_only_non_secret_connection_fields(app):
    from app import smb_share_manager

    user_id = _create_user(app)
    with app.app_context():
        rejected, error = smb_share_manager.upsert_smb_share(user_id, {
            'name': 'Team files',
            'host': 'nas.example',
            'share': 'Docs',
            'domain': 'LAB',
            'username': 'alice',
            'password': 'must-never-be-stored',
        })
        assert rejected is None
        assert error == 'Passwords cannot be saved'

        saved, error = smb_share_manager.upsert_smb_share(user_id, {
            'name': ' Team files ',
            'host': 'NAS.Example',
            'share': 'Docs',
            'domain': ' LAB ',
            'username': ' alice ',
        })

        assert error is None
        assert saved['name'] == 'Team files'
        assert saved['host'] == 'nas.example'
        assert saved['share'] == 'Docs'
        assert saved['domain'] == 'LAB'
        assert saved['username'] == 'alice'
        assert 'password' not in saved
        assert smb_share_manager.load_smb_shares(user_id) == [saved]

        document = json.loads(
            smb_share_manager.get_user_smb_shares_file(user_id).read_text(
                encoding='utf-8'
            )
        )
        assert document['smb_shares'] == [saved]
        assert 'password' not in json.dumps(document).lower()


@pytest.mark.parametrize('secret_field', [
    'password_hash',
    'passphrase',
    'access_token',
    'credential_blob',
])
def test_saved_share_rejects_secret_like_payload_fields(app, secret_field):
    from app import smb_share_manager

    user_id = _create_user(app, f'smb-share-secret-{secret_field}')
    with app.app_context():
        saved, error = smb_share_manager.upsert_smb_share(user_id, {
            'name': 'Team files',
            'host': 'nas.example',
            'share': 'Docs',
            'domain': 'LAB',
            'username': 'alice',
            secret_field: 'must-never-be-stored',
        })

    assert saved is None
    assert error == 'Passwords cannot be saved'


def test_saved_share_update_preserves_identity_and_delete_is_scoped(app):
    from app import smb_share_manager

    user_id = _create_user(app, 'smb-share-update')
    with app.app_context():
        first, error = smb_share_manager.upsert_smb_share(user_id, {
            'name': 'Team files',
            'host': 'nas.example',
            'share': 'Docs',
            'domain': '',
            'username': 'alice',
        })
        assert error is None
        updated, error = smb_share_manager.upsert_smb_share(user_id, {
            'id': first['id'],
            'name': 'Team files',
            'host': 'files.example',
            'share': 'Projects',
            'domain': 'OPS',
            'username': 'alice',
        })

        assert error is None
        assert updated['id'] == first['id']
        assert updated['created_at'] == first['created_at']
        assert updated['updated_at'] != first['updated_at']
        assert smb_share_manager.load_smb_shares(user_id) == [updated]
        assert smb_share_manager.delete_smb_share(user_id, first['id']) == (
            True,
            None,
        )
        assert smb_share_manager.load_smb_shares(user_id) == []
        assert smb_share_manager.delete_smb_share(user_id, first['id']) == (
            False,
            'SMB share not found',
        )


def test_saved_share_limit_rejects_new_entries_but_allows_updates(
        app, monkeypatch):
    from app import smb_share_manager

    monkeypatch.setattr(smb_share_manager.config, 'SMB_MAX_SAVED_SHARES', 2)
    user_id = _create_user(app, 'smb-share-limit')
    base = {
        'host': 'nas.example',
        'share': 'Docs',
        'domain': '',
        'username': 'alice',
    }
    with app.app_context():
        first, error = smb_share_manager.upsert_smb_share(
            user_id, {**base, 'name': 'One'},
        )
        assert error is None
        second, error = smb_share_manager.upsert_smb_share(
            user_id, {**base, 'name': 'Two'},
        )
        assert error is None
        before = smb_share_manager.get_user_smb_shares_file(
            user_id
        ).read_bytes()

        rejected, error = smb_share_manager.upsert_smb_share(
            user_id, {**base, 'name': 'Three'},
        )
        assert rejected is None
        assert error == 'Saved SMB share limit reached'
        assert smb_share_manager.get_user_smb_shares_file(
            user_id
        ).read_bytes() == before

        updated, error = smb_share_manager.upsert_smb_share(user_id, {
            **base,
            'id': first['id'],
            'name': 'One updated',
            'host': 'files.example',
        })
        assert error is None
        assert updated['id'] == first['id']
        assert [item['id'] for item in smb_share_manager.load_smb_shares(
            user_id
        )] == [first['id'], second['id']]


@pytest.mark.parametrize(
    ('field', 'value'),
    [
        ('name', ''),
        ('host', 'bad host'),
        ('share', '../escape'),
        ('domain', 'bad\nvalue'),
        ('username', 'bad\x00value'),
    ],
)
def test_saved_share_rejects_invalid_fields(app, field, value):
    from app import smb_share_manager

    user_id = _create_user(app, f'smb-invalid-{field}')
    payload = {
        'name': 'Team files',
        'host': 'nas.example',
        'share': 'Docs',
        'domain': '',
        'username': 'alice',
    }
    payload[field] = value

    with app.app_context():
        saved, error = smb_share_manager.upsert_smb_share(user_id, payload)

    assert saved is None
    assert error


def test_saved_share_mutation_preserves_corrupt_storage(app):
    from app import smb_share_manager

    user_id = _create_user(app, 'smb-share-corrupt')
    corrupt = b'{"smb_shares": ['
    with app.app_context():
        path = smb_share_manager.get_user_smb_shares_file(user_id)
        path.write_bytes(corrupt)

        with pytest.raises(StorageCorruptionError):
            smb_share_manager.upsert_smb_share(user_id, {
                'name': 'Team files',
                'host': 'nas.example',
                'share': 'Docs',
                'domain': '',
                'username': 'alice',
            })

        assert path.read_bytes() == corrupt


@pytest.mark.parametrize('secret_field', ['password', 'password_hash', 'access_token'])
def test_saved_share_document_with_secret_field_fails_closed(app, secret_field):
    from app import smb_share_manager

    user_id = _create_user(app, f'smb-share-secret-corrupt-{secret_field}')
    with app.app_context():
        path = smb_share_manager.get_user_smb_shares_file(user_id)
        path.write_text(json.dumps({
            'schema_version': 2,
            'smb_shares': [{
                'id': 'share-1',
                'name': 'Unsafe',
                'host': 'nas.example',
                'share': 'Docs',
                'domain': '',
                'username': 'alice',
                secret_field: 'secret',
                'created_at': '2026-08-24T00:00:00+00:00',
                'updated_at': '2026-08-24T00:00:00+00:00',
            }],
        }), encoding='utf-8')

        with pytest.raises(StorageCorruptionError):
            smb_share_manager.load_smb_shares(user_id)


def test_saved_share_document_has_a_hard_item_ceiling(app):
    from app import smb_share_manager

    user_id = _create_user(app, 'smb-share-oversized-document')
    item = {
        'id': 'share-1',
        'name': 'Team files',
        'host': 'nas.example',
        'share': 'Docs',
        'domain': '',
        'username': 'alice',
        'created_at': '2026-08-24T00:00:00+00:00',
        'updated_at': '2026-08-24T00:00:00+00:00',
    }
    with app.app_context():
        path = smb_share_manager.get_user_smb_shares_file(user_id)
        path.write_text(json.dumps({
            'schema_version': 2,
            'smb_shares': [dict(item) for _index in range(1001)],
        }), encoding='utf-8')

        with pytest.raises(StorageCorruptionError):
            smb_share_manager.load_smb_shares(user_id)
