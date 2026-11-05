import hashlib

import pytest

from tests.test_sftp_editor_modes import fixture


@pytest.mark.parametrize('content,expected', [('a\n' * 4, b'a\r\n' * 4), ('a\n' * 5, None)])
def test_sftp_checks_final_encoded_bytes(monkeypatch, content, expected):
    import config
    from app.sftp_handler import write_file_text
    monkeypatch.setattr(config, 'MAX_EDITOR_FILE_SIZE', 12)
    state = fixture(monkeypatch)
    outcome = write_file_text('a', '/file', content, newline='crlf',
                              expected_revision=hashlib.sha256(b'old').hexdigest())
    if expected is None:
        assert not outcome.success
        assert outcome.error == 'File too large to edit'
        assert state['data'] == b'old'
        assert not state['renamed']
    else:
        assert outcome.success, outcome.error
        assert state['data'] == expected
