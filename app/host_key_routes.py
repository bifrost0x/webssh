"""Authenticated management routes for SSH host trust."""

from flask import Blueprint, abort, jsonify
from flask_login import current_user, login_required

import config

from .audit_logger import log_security_event
from .decorators import admin_required
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


@host_key_blueprint.delete("/api/host-keys/<entry_id>")
@login_required
def delete_user_host_key(entry_id):
    _require_enabled()
    store = HostKeyStore(
        current_user.id,
        config.KNOWN_HOSTS_FILE,
        config.USERS_DIR,
    )
    if not store.delete_entry(entry_id):
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


@host_key_blueprint.delete("/admin/api/host-keys/<entry_id>")
@admin_required
@login_required
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
