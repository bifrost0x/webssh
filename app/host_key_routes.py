"""Authenticated management routes for SSH host trust."""

from flask import Blueprint, abort, jsonify, request
from flask_login import current_user, login_required

import config

from .audit_logger import log_security_event
from .decorators import admin_required, step_up_required
from .host_key_store import HostKeyStore


host_key_blueprint = Blueprint("host_keys", __name__)


def _require_enabled():
    if not config.HOST_KEY_MANAGEMENT_ENABLED:
        abort(404)


@host_key_blueprint.get("/api/host-keys")
@login_required
def list_user_host_keys():
    _require_enabled()
    store = HostKeyStore(
        current_user.id,
        config.KNOWN_HOSTS_FILE,
        config.USERS_DIR,
    )
    return jsonify({"entries": store.list_entries()})


def _owned_ssh_targets():
    from .profile_manager import load_profiles
    from .jump_host_manager import load_jump_hosts

    # Never accept hostnames or a user selector from the request: matching a
    # global wildcard/hash must not become an arbitrary host-inventory oracle.
    targets = []
    for kind, records in [('ssh', load_profiles(current_user.id)),
                          ('jump', load_jump_hosts(current_user.id))]:
        for item in records:
            targets.append({'id': item['id'], 'name': item.get('name', ''),
                            'kind': kind, 'host': item['host'],
                            'port': item.get('port') or 22})
    return targets


@host_key_blueprint.get("/api/host-keys/effective")
@login_required
def list_effective_host_keys():
    _require_enabled()
    store = HostKeyStore(current_user.id, config.KNOWN_HOSTS_FILE, config.USERS_DIR)
    response = jsonify({'targets': store.effective_targets(_owned_ssh_targets())})
    response.headers['Cache-Control'] = 'no-store'
    return response


@host_key_blueprint.get("/api/host-keys/<entry_id>/deletion-impact")
@login_required
def preview_user_host_key_deletion(entry_id):
    _require_enabled()
    store = HostKeyStore(current_user.id, config.KNOWN_HOSTS_FILE, config.USERS_DIR)
    impact = store.deletion_impact(entry_id, _owned_ssh_targets())
    if impact is None:
        return jsonify({'error': 'Host key not found'}), 404
    response = jsonify(impact)
    response.headers['Cache-Control'] = 'no-store'
    return response


@host_key_blueprint.delete("/api/host-keys/<entry_id>")
@login_required
def delete_user_host_key(entry_id):
    _require_enabled()
    store = HostKeyStore(
        current_user.id,
        config.KNOWN_HOSTS_FILE,
        config.USERS_DIR,
    )
    try:
        removed = store.delete_entry(entry_id, expected_revision=request.headers.get('If-Match'))
    except ValueError:
        return jsonify({'error': 'Trust changed. Reload and review the deletion again.', 'code': 'trust_changed'}), 409
    if not removed:
        return jsonify({"error": "Host key not found"}), 404
    log_security_event(
        "SSH_HOST_KEY_DELETED",
        user=current_user.username,
        entry_id=entry_id,
    )
    return jsonify({"ok": True})


@host_key_blueprint.get("/admin/api/host-keys")
@admin_required
@login_required
def list_global_host_keys():
    _require_enabled()
    return jsonify({
        "entries": HostKeyStore.list_file(
            config.KNOWN_HOSTS_FILE,
            scope="global",
            owner_id=None,
        )
    })


@host_key_blueprint.post("/admin/api/host-keys")
@admin_required
@login_required
@step_up_required("host_key.global_add", "global")
def add_global_host_key():
    _require_enabled()
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request"}), 400
    entry, error = HostKeyStore.add_file_entry(
        config.KNOWN_HOSTS_FILE,
        data.get("entry"),
        scope="global",
        owner_id=None,
        lock_key="host_keys:global",
    )
    if error:
        status = 409 if "already" in error or "different key" in error else 400
        return jsonify({"error": error}), status
    log_security_event(
        "GLOBAL_SSH_HOST_KEY_ADDED",
        admin=current_user.username,
        hosts=",".join(item["host"] for item in entry["hosts"]),
        algorithm=entry["algorithm"],
        fingerprint=entry["fingerprint"],
        marker=entry["marker"],
    )
    return jsonify({"entry": entry}), 201


@host_key_blueprint.delete("/admin/api/host-keys/<entry_id>")
@admin_required
@login_required
@step_up_required("host_key.global_delete", lambda entry_id: entry_id)
def delete_global_host_key(entry_id):
    _require_enabled()
    removed = HostKeyStore.delete_file_entry(
        config.KNOWN_HOSTS_FILE,
        entry_id,
        scope="global",
        owner_id=None,
        lock_key="host_keys:global",
    )
    if not removed:
        return jsonify({"error": "Host key not found"}), 404
    log_security_event(
        "GLOBAL_SSH_HOST_KEY_DELETED",
        admin=current_user.username,
        entry_id=entry_id,
    )
    return jsonify({"ok": True})
