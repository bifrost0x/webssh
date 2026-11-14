
def test_optional_recovery_marker_failure_cannot_skip_cli_security_sanitization(app, tmp_path, monkeypatch):
    from app import backup_manager, customer_workflows, restore_sanitizer, session_epoch
    archive = tmp_path / 'fixture.zip'
    archive.write_bytes(b'isolated mock archive')
    observed = []
    monkeypatch.setattr(backup_manager, '_restore_archive', lambda *a, **k: observed.append('restore'))
    def fail_marker(*args, **kwargs):
        raise OSError('private path must not escape')
    monkeypatch.setattr(customer_workflows, 'atomic_write_json', fail_marker)
    monkeypatch.setattr(restore_sanitizer, 'sanitize_restored_authentication_state', lambda *a: observed.append('sanitize'))
    monkeypatch.setattr(session_epoch, 'rotate_epoch', lambda: observed.append('epoch'))
    result = app.test_cli_runner().invoke(args=['backup', 'restore', str(archive), '--confirm-offline'])
    assert result.exit_code == 0, result.output
    assert observed == ['restore', 'sanitize', 'epoch']
    assert 'private path must not escape' not in result.output
