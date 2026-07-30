"""Bounded, administrator-only audit export and retention controls."""

import json
from datetime import datetime, timezone
from pathlib import Path

import config
from flask import Blueprint, Response, abort, jsonify, request, stream_with_context
from flask_login import current_user, login_required

from . import audit_logger as audit_logging
from .app_settings import set_audit_backup_count as persist_backup_count
from .audit_logger import apply_audit_backup_count, log_security_event
from .decorators import admin_required


audit_export_blueprint = Blueprint("audit_export", __name__)
AUDIT_LOG_FILE = audit_logging.LOGS_DIR / "security_audit.log"
MAX_EXPORT_SCAN = 50_000


def _parse_timestamp(value):
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _candidate_files(path):
    path = Path(path)
    candidates = [path]
    candidates.extend(
        sorted(
            path.parent.glob(f"{path.name}.*"),
            key=lambda item: (
                int(item.suffix[1:])
                if item.suffix[1:].isdigit()
                else -1
            ),
        )
    )
    return candidates


def audit_scan_metadata(
    path,
    *,
    max_scan=MAX_EXPORT_SCAN,
):
    scanned = 0
    for candidate in _candidate_files(path):
        if not candidate.is_file():
            continue
        for _line in audit_logging._iter_log_lines_newest_first(candidate):
            if scanned >= max_scan:
                return {
                    "scanned": scanned,
                    "truncated": True,
                    "scan_limit": max_scan,
                }
            scanned += 1
    return {
        "scanned": scanned,
        "truncated": False,
        "scan_limit": max_scan,
    }


def iter_audit_records(
    path,
    *,
    start=None,
    end=None,
    level=None,
    query=None,
    max_scan=MAX_EXPORT_SCAN,
):
    scanned = 0
    normalized_level = level.upper() if level else None
    normalized_query = query.lower() if query else None
    for candidate in _candidate_files(path):
        if not candidate.is_file():
            continue
        for line in audit_logging._iter_log_lines_newest_first(candidate):
            if scanned >= max_scan:
                return
            scanned += 1
            try:
                record = json.loads(line)
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(record, dict):
                continue
            try:
                timestamp = _parse_timestamp(record.get("timestamp"))
            except (TypeError, ValueError):
                continue
            if start and (timestamp is None or timestamp < start):
                continue
            if end and (timestamp is None or timestamp > end):
                continue
            if normalized_level and str(
                record.get("level", "")
            ).upper() != normalized_level:
                continue
            if normalized_query and normalized_query not in json.dumps(
                record,
                ensure_ascii=False,
            ).lower():
                continue
            yield record


def set_audit_backup_count(value):
    if persist_backup_count(value) is False:
        return False
    apply_audit_backup_count(value)
    return value


def _require_enabled():
    if not config.AUDIT_EXPORT_ENABLED:
        abort(404)


@audit_export_blueprint.get("/admin/api/audit/export")
@admin_required
@login_required
def export_audit_log():
    _require_enabled()
    try:
        start = _parse_timestamp(request.args.get("from"))
        end = _parse_timestamp(request.args.get("to"))
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid audit export timestamp"}), 400
    if start and end and start > end:
        return jsonify({"error": "Invalid audit export range"}), 400

    if request.method != "HEAD":
        log_security_event(
            "AUDIT_EXPORT",
            admin=current_user.username,
        )
    metadata = audit_scan_metadata(
        AUDIT_LOG_FILE,
        max_scan=MAX_EXPORT_SCAN,
    )
    records = iter_audit_records(
        AUDIT_LOG_FILE,
        start=start,
        end=end,
        level=request.args.get("level") or None,
        query=request.args.get("q") or None,
        max_scan=MAX_EXPORT_SCAN,
    )

    def generate():
        export_metadata = {
            "type": "webssh_audit_export",
            **metadata,
        }
        yield json.dumps(export_metadata, separators=(",", ":")) + "\n"
        for record in records:
            yield json.dumps(
                record,
                ensure_ascii=False,
                separators=(",", ":"),
            ) + "\n"

    response = Response(
        stream_with_context(generate()),
        mimetype="application/x-ndjson",
    )
    response.headers[
        "Content-Disposition"
    ] = 'attachment; filename="webssh-audit.jsonl"'
    response.headers["X-WebSSH-Audit-Scan-Limit"] = str(MAX_EXPORT_SCAN)
    response.headers["X-WebSSH-Audit-Scanned"] = str(metadata["scanned"])
    response.headers["X-WebSSH-Audit-Truncated"] = str(
        metadata["truncated"]
    ).lower()
    response.headers["X-WebSSH-Audit-Completeness"] = (
        "truncated"
        if metadata["truncated"]
        else "complete-within-retained-logs"
    )
    return response


@audit_export_blueprint.post("/admin/api/audit/retention")
@admin_required
@login_required
def update_audit_retention():
    _require_enabled()
    data = request.get_json(silent=True) or {}
    value = data.get("backup_count")
    if type(value) is not int or not 1 <= value <= 90:
        return jsonify({
            "error": "backup_count must be an integer between 1 and 90"
        }), 400
    if set_audit_backup_count(value) is False:
        return jsonify({"error": "Audit retention could not be saved"}), 503
    log_security_event(
        "AUDIT_RETENTION_CHANGED",
        admin=current_user.username,
        backup_count=value,
    )
    return jsonify({"backup_count": value})
