from pathlib import Path


def _read(path):
    return Path(path).read_text(encoding='utf-8')


def test_all_key_connection_forms_have_transient_passphrase_fields():
    template = _read('templates/index.html')
    sftp = _read('static/js/sftp-file-manager.js')

    assert 'id="keyPassphraseInput"' in template
    assert 'id="jumpHostKeyPassphraseInput"' in template
    assert 'id="keyUploadPassphraseInput"' in template
    assert 'id="fmQcKeyPassphrase"' in sftp
    assert template.count('autocomplete="off"') >= 3
    assert 'autocomplete="off"' in sftp


def test_frontend_sends_and_clears_each_passphrase_field():
    app_source = _read('static/js/app.js')
    sftp_source = _read('static/js/sftp-file-manager.js')

    assert 'connectionData.key_passphrase = keyPassphrase' in app_source
    assert 'proxyJump.key_passphrase = jhKeyPassphrase' in app_source
    assert "keyPassphraseInput.value = ''" in app_source
    assert "getElementById('keyPassphraseInput').value = ''" in app_source
    assert "getElementById('jumpHostKeyPassphraseInput').value = ''" in app_source
    assert 'data.key_passphrase = keyPassphrase' in sftp_source
    assert "keyPassphraseInput.value = ''" in sftp_source


def test_encrypted_key_reconnect_reopens_form_and_never_uses_local_storage():
    sources = [
        _read('static/js/app.js'),
        _read('static/js/profile-manager.js'),
        _read('static/js/session-manager.js'),
        _read('static/js/sftp-file-manager.js'),
    ]
    session_source = sources[2]

    assert '!session.keyPassphraseRequired' in session_source
    assert 'if (session.keyPassphraseRequired)' in session_source
    assert 'this.prefillConnectionForm(sessionId)' in session_source
    assert all('localStorage.setItem' not in line or 'passphrase' not in line.lower()
               for source in sources for line in source.splitlines())
