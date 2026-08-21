import logging


def test_security_event_redacts_sensitive_details(caplog):
    from app.audit_logger import log_security_event

    exposed_password = "must-not-reach-the-audit-log"
    caplog.set_level(logging.INFO, logger="security_audit")

    log_security_event(
        "AUDIT_REDACTION_TEST",
        user="audit-user",
        password=exposed_password,
    )

    record = next(
        item
        for item in caplog.records
        if item.name == "security_audit"
        and item.getMessage().startswith("AUDIT_REDACTION_TEST")
    )
    assert "user=audit-user" in record.getMessage()
    assert "password=[REDACTED]" in record.getMessage()
    assert exposed_password not in record.getMessage()


def test_cli_audit_redacts_sensitive_nested_details(caplog):
    from app.cli import _audit_operation

    exposed_token = "must-not-reach-structured-audit-data"
    exposed_password_hash = "must-not-reach-structured-audit-data-either"
    caplog.set_level(logging.INFO, logger="security_audit")

    _audit_operation(
        "CLI_AUDIT_REDACTION_TEST",
        action="verified",
        provider={
            "access_token": exposed_token,
            "name": "example",
            "password_hash": exposed_password_hash,
        },
    )

    record = next(
        item
        for item in caplog.records
        if item.name == "security_audit"
        and item.getMessage() == "CLI_AUDIT_REDACTION_TEST"
    )
    assert record.extra_data == {
        "action": "verified",
        "provider": {
            "access_token": "[REDACTED]",
            "name": "example",
            "password_hash": "[REDACTED]",
        },
    }
    assert exposed_token not in repr(record.extra_data)
    assert exposed_password_hash not in repr(record.extra_data)
