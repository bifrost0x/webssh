"""Security and streaming behavior for audit export and retention."""

import json
from logging.handlers import RotatingFileHandler


def _create_user(app, username, *, is_admin=False):
    from app.auth import register_user
    from app.models import db

    with app.app_context():
        user, error = register_user(username, "password123")
        assert error is None
        user.is_admin = is_admin
        db.session.commit()


def _login(client, username):
    response = client.post(
        "/login",
        data={"username": username, "password": "password123"},
    )
    assert response.status_code == 302


def test_audit_export_is_admin_only(app, client):
    _create_user(app, "normal")
    _login(client, "normal")

    response = client.get("/admin/api/audit/export")

    assert response.status_code == 403


def test_audit_export_streams_filtered_bounded_jsonl(
    app, client, tmp_path, monkeypatch
):
    from app import audit_export

    _create_user(app, "admin", is_admin=True)
    _login(client, "admin")
    log_path = tmp_path / "security_audit.log"
    records = [
        {
            "timestamp": "2026-07-29T09:00:00Z",
            "level": "INFO",
            "message": "LOGIN_SUCCESS user=alice",
        },
        {
            "timestamp": "2026-07-30T10:00:00Z",
            "level": "WARNING",
            "message": "SSH_CONNECT_FAILED user=bob",
        },
        {
            "timestamp": "2026-07-30T11:00:00Z",
            "level": "INFO",
            "message": "LOGIN_SUCCESS user=carol",
        },
    ]
    log_path.write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )
    monkeypatch.setattr(audit_export, "AUDIT_LOG_FILE", log_path)
    monkeypatch.setattr(audit_export, "MAX_EXPORT_SCAN", 2)

    response = client.get(
        "/admin/api/audit/export"
        "?from=2026-07-30T00:00:00Z&level=INFO&q=LOGIN"
    )

    assert response.status_code == 200
    assert response.mimetype == "application/x-ndjson"
    exported = [
        json.loads(line)
        for line in response.get_data(as_text=True).splitlines()
    ]
    assert exported == [
        {
            "type": "webssh_audit_export",
            "truncated": True,
            "scanned": 2,
            "scan_limit": 2,
        },
        records[2],
    ]
    assert "attachment;" in response.headers["Content-Disposition"]
    assert response.headers["X-WebSSH-Audit-Scan-Limit"] == "2"
    assert response.headers["X-WebSSH-Audit-Scanned"] == "2"
    assert response.headers["X-WebSSH-Audit-Truncated"] == "true"
    assert response.headers["X-WebSSH-Audit-Completeness"] == "truncated"


def test_audit_export_reports_complete_when_scan_limit_is_not_reached(
    app, client, tmp_path, monkeypatch
):
    from app import audit_export

    _create_user(app, "admin", is_admin=True)
    _login(client, "admin")
    log_path = tmp_path / "security_audit.log"
    records = [
        {
            "timestamp": "2026-07-30T10:00:00Z",
            "level": "INFO",
            "message": "LOGIN_SUCCESS user=alice",
        },
        {
            "timestamp": "2026-07-30T11:00:00Z",
            "level": "INFO",
            "message": "LOGIN_SUCCESS user=bob",
        },
    ]
    log_path.write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )
    monkeypatch.setattr(audit_export, "AUDIT_LOG_FILE", log_path)
    monkeypatch.setattr(audit_export, "MAX_EXPORT_SCAN", 2)

    response = client.get("/admin/api/audit/export")
    exported = [
        json.loads(line)
        for line in response.get_data(as_text=True).splitlines()
    ]

    assert exported[0] == {
        "type": "webssh_audit_export",
        "truncated": False,
        "scanned": 2,
        "scan_limit": 2,
    }
    assert exported[1:] == list(reversed(records))
    assert response.headers["X-WebSSH-Audit-Scanned"] == "2"
    assert response.headers["X-WebSSH-Audit-Truncated"] == "false"
    assert (
        response.headers["X-WebSSH-Audit-Completeness"]
        == "complete-within-retained-logs"
    )


def test_audit_export_event_is_written_before_the_export_snapshot(
    app, client, tmp_path, monkeypatch
):
    from app import audit_export

    _create_user(app, "admin", is_admin=True)
    _login(client, "admin")
    log_path = tmp_path / "security_audit.log"
    original = {
        "timestamp": "2026-07-30T10:00:00Z",
        "level": "INFO",
        "message": "LOGIN_SUCCESS user=alice",
    }
    export_event = {
        "timestamp": "2026-07-30T11:00:00Z",
        "level": "INFO",
        "message": "AUDIT_EXPORT admin=admin",
    }
    log_path.write_text(json.dumps(original) + "\n", encoding="utf-8")
    monkeypatch.setattr(audit_export, "AUDIT_LOG_FILE", log_path)
    monkeypatch.setattr(audit_export, "MAX_EXPORT_SCAN", 2)

    def write_export_event(*_args, **_kwargs):
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(export_event) + "\n")

    monkeypatch.setattr(
        audit_export,
        "log_security_event",
        write_export_event,
    )

    response = client.get("/admin/api/audit/export")
    exported = [
        json.loads(line)
        for line in response.get_data(as_text=True).splitlines()
    ]

    assert exported[0]["scanned"] == 2
    assert exported[0]["truncated"] is False
    assert exported[1:] == [export_event, original]


def test_retention_rejects_out_of_range_without_changing_handlers(
    app, client, monkeypatch
):
    from app import audit_export

    _create_user(app, "admin", is_admin=True)
    _login(client, "admin")
    calls = []
    monkeypatch.setattr(
        audit_export,
        "set_audit_backup_count",
        lambda value: calls.append(value),
    )

    response = client.post(
        "/admin/api/audit/retention",
        json={"backup_count": 0},
    )

    assert response.status_code == 400
    assert calls == []


def test_retention_endpoint_applies_selected_backup_count(
    app, client, monkeypatch
):
    from app import audit_export

    _create_user(app, "admin", is_admin=True)
    _login(client, "admin")
    calls = []
    monkeypatch.setattr(
        audit_export,
        "set_audit_backup_count",
        lambda value: calls.append(value),
    )

    response = client.post(
        "/admin/api/audit/retention",
        json={"backup_count": 14},
    )

    assert response.status_code == 200
    assert response.get_json() == {"backup_count": 14}
    assert calls == [14]


def test_reducing_retention_prunes_archives_beyond_new_limit(
    tmp_path, monkeypatch
):
    import logging
    from app import audit_logger

    log_path = tmp_path / 'security_audit.log'
    log_path.write_text('current', encoding='utf-8')
    for index in range(1, 5):
        (tmp_path / f'security_audit.log.{index}').write_text(
            str(index), encoding='utf-8'
        )

    logger = logging.getLogger(f'audit-retention-{id(tmp_path)}')
    logger.handlers.clear()
    handler = RotatingFileHandler(
        log_path,
        maxBytes=1024,
        backupCount=5,
        encoding='utf-8',
    )
    logger.addHandler(handler)
    monkeypatch.setattr(audit_logger, 'app_logger', logger)
    monkeypatch.setattr(audit_logger, 'audit_logger', logging.getLogger(
        f'audit-retention-empty-{id(tmp_path)}'
    ))

    try:
        assert audit_logger.apply_audit_backup_count(1) == 1
        assert handler.backupCount == 1
        assert (tmp_path / 'security_audit.log.1').exists()
        assert not (tmp_path / 'security_audit.log.2').exists()
        assert not (tmp_path / 'security_audit.log.3').exists()
        assert not (tmp_path / 'security_audit.log.4').exists()
    finally:
        handler.close()
        logger.handlers.clear()


def test_retention_prune_failure_does_not_block_runtime_configuration(
    tmp_path, monkeypatch, caplog
):
    import logging
    from pathlib import Path
    from app import audit_logger

    log_path = tmp_path / 'security_audit.log'
    log_path.write_text('current', encoding='utf-8')
    locked_archive = tmp_path / 'security_audit.log.2'
    locked_archive.write_text('locked', encoding='utf-8')

    logger = logging.getLogger(f'audit-retention-locked-{id(tmp_path)}')
    logger.handlers.clear()
    handler = RotatingFileHandler(
        log_path,
        maxBytes=1024,
        backupCount=5,
        encoding='utf-8',
    )
    logger.addHandler(handler)
    monkeypatch.setattr(audit_logger, 'app_logger', logger)
    monkeypatch.setattr(audit_logger, 'audit_logger', logging.getLogger(
        f'audit-retention-locked-empty-{id(tmp_path)}'
    ))
    original_unlink = Path.unlink

    def reject_locked_archive(path, *args, **kwargs):
        if path == locked_archive:
            raise PermissionError('archive is locked')
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'unlink', reject_locked_archive)

    try:
        with caplog.at_level(logging.WARNING):
            assert audit_logger.apply_audit_backup_count(1) == 1
        assert handler.backupCount == 1
        assert locked_archive.exists()
        assert 'Audit log archive pruning deferred' in caplog.text
    finally:
        handler.close()
        logger.handlers.clear()


def test_persisted_retention_is_applied_to_active_handlers(
    app, tmp_path, monkeypatch
):
    from app import app_settings, audit_logger
    from app.storage_migrations import CURRENT_STORAGE_VERSIONS

    settings_path = tmp_path / "app_settings.json"
    settings_path.write_text(json.dumps({
        "schema_version": CURRENT_STORAGE_VERSIONS["app_settings"],
        "audit_backup_count": 17,
    }), encoding="utf-8")
    monkeypatch.setattr(app_settings, "_SETTINGS_FILE", settings_path)
    handlers = [
        handler
        for logger in (audit_logger.app_logger, audit_logger.audit_logger)
        for handler in logger.handlers
        if isinstance(handler, RotatingFileHandler)
    ]
    original = [handler.backupCount for handler in handlers]
    try:
        assert audit_logger.apply_audit_backup_count() == 17
        assert all(handler.backupCount == 17 for handler in handlers)
    finally:
        for handler, backup_count in zip(handlers, original):
            handler.backupCount = backup_count
