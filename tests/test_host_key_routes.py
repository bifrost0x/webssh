"""Authorization and disclosure boundaries for host-key management."""

import paramiko

from tests.step_up_helpers import password_step_up_headers


def _create_user(app, username, *, is_admin=False):
    from app.auth import register_user
    from app.models import db

    with app.app_context():
        user, error = register_user(username, "password123")
        assert error is None
        user.is_admin = is_admin
        db.session.commit()
        return user.id


def _login(client, username):
    response = client.post(
        "/login",
        data={"username": username, "password": "password123"},
    )
    assert response.status_code == 302


def _write_key(path, hostname):
    path.parent.mkdir(parents=True, exist_ok=True)
    key = paramiko.RSAKey.generate(1024)
    keys = paramiko.HostKeys()
    keys.add(hostname, key.get_name(), key)
    keys.save(str(path))
    return key


def test_user_can_list_and_delete_only_their_own_host_keys(app, client):
    import config

    owner_id = _create_user(app, "owner")
    other_id = _create_user(app, "other")
    _write_key(config.USERS_DIR / f"user_{owner_id}" / "known_hosts", "owner.example")
    _write_key(config.USERS_DIR / f"user_{other_id}" / "known_hosts", "other.example")
    _login(client, "owner")

    listed = client.get("/api/host-keys")

    assert listed.status_code == 200
    entries = listed.get_json()["entries"]
    assert [entry["host"] for entry in entries] == ["owner.example"]
    assert set(entries[0]) == {
        "id",
            "host",
            "hosts",
            "marker",
            "port",
        "algorithm",
        "fingerprint",
        "scope",
        "owner_id",
        "first_seen",
        "last_seen",
    }
    assert entries[0]["scope"] == "user"
    assert entries[0]["hosts"] == [{"host": "owner.example", "port": 22}]
    assert entries[0]["marker"] is None
    assert entries[0]["owner_id"] == owner_id
    assert "ssh-rsa " not in str(entries)

    deleted = client.delete(f"/api/host-keys/{entries[0]['id']}")

    assert deleted.status_code == 200
    assert client.get("/api/host-keys").get_json()["entries"] == []
    other_keys = paramiko.HostKeys(
        str(config.USERS_DIR / f"user_{other_id}" / "known_hosts")
    )
    assert other_keys.lookup("other.example") is not None


def test_admin_global_host_key_routes_reject_normal_users(app, client):
    _create_user(app, "normal")
    _login(client, "normal")

    response = client.get("/admin/api/host-keys")

    assert response.status_code == 403


def test_admin_can_manage_global_host_keys_without_raw_key_material(app, client):
    import config

    _create_user(app, "admin", is_admin=True)
    _write_key(config.KNOWN_HOSTS_FILE, "[global.example]:2222")
    _login(client, "admin")

    listed = client.get("/admin/api/host-keys")

    assert listed.status_code == 200
    entries = listed.get_json()["entries"]
    assert len(entries) == 1
    assert entries[0]["host"] == "global.example"
    assert entries[0]["port"] == 2222
    assert entries[0]["scope"] == "global"
    assert entries[0]["owner_id"] is None
    assert entries[0]["fingerprint"].startswith("SHA256:")
    assert "ssh-rsa " not in listed.get_data(as_text=True)

    entry_id = entries[0]["id"]
    deleted = client.delete(
        f"/admin/api/host-keys/{entry_id}",
        headers=password_step_up_headers(
            client, "host_key.global_delete", entry_id
        )[0],
    )

    assert deleted.status_code == 200
    assert client.get("/admin/api/host-keys").get_json()["entries"] == []


def test_admin_can_import_one_verified_global_host_key(app, client):
    import config

    _create_user(app, "admin", is_admin=True)
    _login(client, "admin")
    key = paramiko.RSAKey.generate(1024)
    raw_entry = f"global.example {key.get_name()} {key.get_base64()}"
    headers, _verified = password_step_up_headers(
        client, "host_key.global_add", "global"
    )

    response = client.post(
        "/admin/api/host-keys",
        json={"entry": raw_entry},
        headers=headers,
    )

    assert response.status_code == 201
    payload = response.get_json()["entry"]
    assert payload["host"] == "global.example"
    assert payload["scope"] == "global"
    assert key.get_base64() not in response.get_data(as_text=True)
    assert config.KNOWN_HOSTS_FILE.read_text(encoding="utf-8") == raw_entry + "\n"


def test_global_host_key_import_rejects_normal_user(app, client):
    _create_user(app, "normal")
    _login(client, "normal")

    response = client.post(
        "/admin/api/host-keys",
        json={"entry": "not a key"},
    )

    assert response.status_code == 403


def test_multi_host_and_revoked_records_disclose_full_deletion_scope(
    app, client
):
    import config

    _create_user(app, "admin", is_admin=True)
    key = paramiko.RSAKey.generate(1024)
    config.KNOWN_HOSTS_FILE.write_text(
        f"host1.example,host2.example {key.get_name()} {key.get_base64()}\n"
        f"@revoked old.example {key.get_name()} {key.get_base64()}\n",
        encoding="utf-8",
    )
    _login(client, "admin")

    entries = client.get("/admin/api/host-keys").get_json()["entries"]

    assert entries[0]["hosts"] == [
        {"host": "host1.example", "port": 22},
        {"host": "host2.example", "port": 22},
    ]
    assert entries[0]["marker"] is None
    assert entries[1]["hosts"] == [{"host": "old.example", "port": 22}]
    assert entries[1]["marker"] == "@revoked"
