"""The main page carries the signed-in user's saved hosts for the first render."""

import json
import re


def _sign_in(app, client, username):
    from app.auth import register_user

    with app.app_context():
        user, error = register_user(username, 'password123')
        assert error is None
        user_id = user.id
    assert client.post('/login', data={'username': username, 'password': 'password123'}).status_code == 302
    return user_id


def _inventory(response):
    match = re.search(rb'<script id="initialInventory" type="application/json">(.*?)</script>', response.data, re.S)
    return json.loads(match.group(1)) if match else None


def test_index_embeds_only_the_users_own_hosts_as_inert_json(app, client):
    from app import profile_manager
    from app.auth import register_user

    with app.app_context():
        other, error = register_user('inventory_other', 'password123')
        assert error is None
        _, error = profile_manager.add_profile(other.id, 'Foreign host', 'foreign.example', 22, 'ops', 'password')
        assert error is None
    user_id = _sign_in(app, client, 'inventory_owner')
    hostile = '</script><script>alert(1)</script>'
    with app.app_context():
        _, error = profile_manager.add_profile(user_id, hostile, 'own.example', 22, 'ops', 'password')
        assert error is None

    response = client.get('/')

    assert response.status_code == 200
    assert response.headers['Cache-Control'] == 'no-store'
    assert b'<script>alert(1)' not in response.data
    inventory = _inventory(response)
    assert [profile['name'] for profile in inventory['profiles']] == [hostile]
    assert inventory['jump_hosts'] == []
    assert b'foreign.example' not in response.data


def test_index_still_renders_when_saved_hosts_cannot_be_read(app, client, monkeypatch):
    from app import profile_manager
    from app.storage_errors import StorageCorruptionError

    _sign_in(app, client, 'inventory_broken')

    def broken(_user_id):
        raise StorageCorruptionError('profiles unreadable')

    monkeypatch.setattr(profile_manager, 'load_profiles', broken)

    response = client.get('/')

    assert response.status_code == 200
    assert _inventory(response) is None
