import json
import logging
import uuid

import config
from app import audit_logger
from app.audit_logger import setup_logger


def test_file_logging_rotates_with_bounded_valid_json_backups(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(config, 'AUDIT_LOG_MAX_BYTES', 180, raising=False)
    monkeypatch.setattr(config, 'AUDIT_LOG_BACKUP_COUNT', 2, raising=False)
    log_path = tmp_path / 'security_audit.log'
    logger = setup_logger(
        f'test-audit-rotation-{uuid.uuid4()}',
        log_file=log_path,
    )

    try:
        for sequence in range(40):
            logger.info('record-%02d-%s', sequence, 'x' * 40)
        for handler in logger.handlers:
            handler.flush()
    finally:
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            handler.close()

    log_files = sorted(tmp_path.glob('security_audit.log*'))
    assert len(log_files) == 3

    for rotated_log in log_files:
        lines = rotated_log.read_text(encoding='utf-8').splitlines()
        assert lines
        for line in lines:
            record = json.loads(line)
            assert record['logger'] == logger.name
            assert record['level'] == logging.getLevelName(logging.INFO)


def test_audit_reader_includes_rotated_backups_newest_first(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(audit_logger, 'LOGS_DIR', tmp_path)
    monkeypatch.setattr(config, 'AUDIT_LOG_BACKUP_COUNT', 2)

    records_by_file = {
        'security_audit.log.2': ['oldest'],
        'security_audit.log.1': ['older', 'old'],
        'security_audit.log': ['newer', 'newest'],
    }
    for filename, messages in records_by_file.items():
        content = ''.join(
            json.dumps({
                'timestamp': message,
                'level': 'INFO',
                'logger': 'security_audit',
                'message': message,
            }) + '\n'
            for message in messages
        )
        (tmp_path / filename).write_text(content, encoding='utf-8')

    result = audit_logger.read_audit_logs()

    assert [item['message'] for item in result['items']] == [
        'newest',
        'newer',
        'old',
        'older',
        'oldest',
    ]


def test_audit_reader_stops_before_older_backups_at_scan_limit(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(audit_logger, 'LOGS_DIR', tmp_path)
    monkeypatch.setattr(config, 'AUDIT_LOG_BACKUP_COUNT', 1)
    active_log = tmp_path / 'security_audit.log'
    active_log.write_text(
        ''.join(
            json.dumps({
                'timestamp': message,
                'level': 'INFO',
                'logger': 'security_audit',
                'message': message,
            }) + '\n'
            for message in ('newer', 'newest')
        ),
        encoding='utf-8',
    )
    (tmp_path / 'security_audit.log.1').write_text(
        '{"message":"must-not-be-read"}\n',
        encoding='utf-8',
    )
    real_open = open

    class UnexpectedBackupRead(BaseException):
        pass

    def guarded_open(path, *args, **kwargs):
        if str(path).endswith('security_audit.log.1'):
            raise UnexpectedBackupRead()
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(audit_logger, 'open', guarded_open, raising=False)

    result = audit_logger.read_audit_logs(max_scan=2)

    assert [item['message'] for item in result['items']] == [
        'newest',
        'newer',
    ]


def test_logger_setup_removes_backups_above_reduced_retention(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(config, 'AUDIT_LOG_MAX_BYTES', 1024)
    monkeypatch.setattr(config, 'AUDIT_LOG_BACKUP_COUNT', 2)
    log_path = tmp_path / 'security_audit.log'
    retained = [
        tmp_path / 'security_audit.log.1',
        tmp_path / 'security_audit.log.2',
    ]
    stale = [
        tmp_path / 'security_audit.log.3',
        tmp_path / 'security_audit.log.4',
    ]
    for backup in retained + stale:
        backup.write_text('{}\n', encoding='utf-8')

    logger = setup_logger(
        f'test-audit-retention-{uuid.uuid4()}',
        log_file=log_path,
    )
    try:
        assert all(backup.exists() for backup in retained)
        assert all(not backup.exists() for backup in stale)
    finally:
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            handler.close()


def test_audit_reader_with_zero_scan_budget_reads_no_records(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(audit_logger, 'LOGS_DIR', tmp_path)
    (tmp_path / 'security_audit.log').write_text(
        '{"message":"must-not-be-returned"}\n',
        encoding='utf-8',
    )

    result = audit_logger.read_audit_logs(max_scan=0)

    assert result['items'] == []
    assert result['total'] == 0
