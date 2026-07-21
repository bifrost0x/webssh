"""Source contracts that prevent startup commands leaking between targets."""

import re
from pathlib import Path


def _source(path):
    return Path(path).read_text(encoding='utf-8')


def test_app_exposes_a_complete_connection_profile_reset_helper():
    source = _source('static/js/app.js')

    helper = re.search(
        r'window\.clearConnectionProfileState\s*=\s*\(\)\s*=>\s*\{(?P<body>.*?)\n\s*\};',
        source,
        re.DOTALL,
    )

    assert helper is not None
    assert "document.getElementById('startupCommandsInput')" in helper.group('body')
    assert re.search(r'startupCommandsInput\.value\s*=\s*[\'\"]{2}', helper.group('body'))
    assert "document.getElementById('profileSelect')" in helper.group('body')
    assert re.search(r'profileSelect\.value\s*=\s*[\'\"]{2}', helper.group('body'))
    assert "document.getElementById('deleteProfileBtn')" in helper.group('body')
    assert re.search(r"deleteProfileBtn\.style\.display\s*=\s*'none'", helper.group('body'))
    assert 'delete deleteProfileBtn.dataset.profileId' in helper.group('body')


def test_new_connection_and_history_target_selection_clear_startup_commands():
    source = _source('static/js/app.js')

    modal = source[source.index('function openConnectionModalForPane'):source.index(
        'function queuePaneConnection'
    )]
    history_click = source[source.index("option.addEventListener('click'"):source.index(
        'container.appendChild(option)', source.index("option.addEventListener('click'")
    )]

    assert 'window.clearConnectionProfileState();' in modal
    assert history_click.index('window.clearConnectionProfileState();') < history_click.index(
        "document.getElementById('hostInput').value = conn.host"
    )


def test_all_session_manager_form_prefills_clear_startup_commands_first():
    source = _source('static/js/session-manager.js')
    password_reconnect = source[source.index('// No key_id'):source.index(
        '        }\n', source.index('// No key_id')
    )]
    prefill = source[source.index('    prefillConnectionForm(sessionId)'):source.index(
        '    directReconnect(sessionId)'
    )]

    assert password_reconnect.index('window.clearConnectionProfileState();') < password_reconnect.index(
        "document.getElementById('hostInput')"
    )
    assert prefill.index('window.clearConnectionProfileState();') < prefill.index(
        "document.getElementById('hostInput')"
    )


def test_submit_does_not_clear_commands_before_validation_can_finish():
    source = _source('static/js/app.js')
    submit = source[source.index("getElementById('connectionForm').addEventListener('submit'"):]
    before_emit = submit[:submit.index("socket.emit('ssh_connect'")]

    assert 'clearConnectionProfileState' not in before_emit
