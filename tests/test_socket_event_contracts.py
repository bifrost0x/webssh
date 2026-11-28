"""Regression checks for the reviewed Socket.IO contract inventory.

The Go server answers the frontend's Socket.IO events through the realtime
shim: its area tables (static/js/realtime-shim-*.js) map each request event
to a v1 request and rebuild the response events the pages listen for, and
realtime-terminal.js handles the terminal events.
"""
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PAGES = ROOT / 'internal' / 'httpapi' / 'pages'
LOGIN_TEMPLATE = PAGES / 'login.gohtml'
BINARY_TRANSFER_CLIENT = ROOT / 'static' / 'js' / 'binary-transfer-client.js'
AUTHENTICATED_TEMPLATE = PAGES / 'index.gohtml'
AUTHENTICATED_APP = ROOT / 'static' / 'js' / 'app.js'
SECURITY_TEMPLATE = PAGES / 'security.gohtml'
TERMINAL_SHIM = ROOT / 'static' / 'js' / 'realtime-terminal.js'

STALE_SERVER_EVENTS = {'detect_os', 'get_sessions'}
RETAINED_SERVER_EVENTS = {
    'quick_disconnect',
    'list_profiles',
    'save_profile',
    'delete_profile',
    'update_profile_organization',
    'list_command_sets',
    'save_command_set',
    'duplicate_command_set',
    'delete_command_set',
    'convert_legacy_command_set',
}
RETAINED_RESPONSE_EVENTS = {
    'profiles_list',
    'profile_saved',
    'profile_deleted',
    'command_sets_list',
    'command_set_saved',
    'command_set_deleted',
    'command_set_converted',
    'quick_disconnect_success',
}

# Answered by the acknowledgement alone; no page listens for the push the
# Python release also sent (profile_organization_updated).
ACKNOWLEDGEMENT_ONLY_RESPONSE_EVENTS = {'profile_organization_updated'}

TRANSFER_CONTROL_EVENTS = {'prepare_transfer', 'cancel_transfer'}


def _area_sources():
    paths = sorted((ROOT / 'static' / 'js').glob('realtime-shim-*.js'))
    assert paths, 'no realtime shim areas found'
    return '\n'.join(path.read_text(encoding='utf-8') for path in paths)


def _server_inventory():
    """Request events the shim answers and response events it pushes."""
    source = _area_sources()
    handlers = set(re.findall(r'^\s+([a-z0-9_]+): \{', source, re.MULTILINE))
    handlers |= set(re.findall(r'^\s+([a-z0-9_]+): \(', TERMINAL_SHIM.read_text(encoding='utf-8'), re.MULTILINE))
    emitted = set(re.findall(r"\[\s*'([a-z0-9_]+)',", source))
    return handlers, emitted


def test_reviewed_stale_server_handlers_are_absent():
    handlers, _ = _server_inventory()

    assert handlers.isdisjoint(STALE_SERVER_EVENTS)


def test_profile_command_set_and_integration_contracts_remain_registered():
    handlers, emitted = _server_inventory()

    assert RETAINED_SERVER_EVENTS <= handlers
    assert RETAINED_RESPONSE_EVENTS <= emitted
    pages = '\n'.join(path.read_text(encoding='utf-8') for path in (ROOT / 'static' / 'js').glob('*.js'))
    for event in ACKNOWLEDGEMENT_ONLY_RESPONSE_EVENTS:
        assert f"'{event}'" not in pages


def test_herdr_snapshot_is_answered_by_acknowledgement_only():
    handlers, emitted = _server_inventory()

    assert 'request_herdr_snapshot' in handlers
    assert not any(event.startswith('herdr') for event in emitted)


def test_transfer_control_contracts_have_client_and_server_halves():
    handlers, _ = _server_inventory()
    client_source = BINARY_TRANSFER_CLIENT.read_text(encoding='utf-8')

    assert TRANSFER_CONTROL_EVENTS <= handlers
    for event in TRANSFER_CONTROL_EVENTS:
        assert f"this.socket.emit('{event}'" in client_source


def test_login_template_has_no_unauthenticated_password_change_action():
    login_template = LOGIN_TEMPLATE.read_text(encoding='utf-8')
    authenticated_template = AUTHENTICATED_TEMPLATE.read_text(encoding='utf-8')
    security_template = SECURITY_TEMPLATE.read_text(encoding='utf-8')

    assert '/change-password' not in login_template
    assert 'id="changePasswordBtn"' not in authenticated_template
    assert 'id="password"' in security_template
    assert 'id="securityChangePasswordBtn"' in security_template
    assert '{{$.URL "/change-password"}}' in security_template


def test_password_actions_navigate_through_security_center():
    app_source = (ROOT / 'static' / 'js' / 'app.js').read_text(encoding='utf-8')

    assert "APP_ROOT + '/security#password'" in app_source
    assert "getElementById('changePasswordBtn')" not in app_source


def test_ssh_authentication_banner_has_mandatory_safe_client_contract():
    handlers, _ = _server_inventory()
    template = AUTHENTICATED_TEMPLATE.read_text(encoding='utf-8')
    app_source = AUTHENTICATED_APP.read_text(encoding='utf-8')
    terminal_shim = TERMINAL_SHIM.read_text(encoding='utf-8')

    assert 'ssh_auth_banner_decision' in handlers
    assert "host.dispatch('ssh_auth_banner'" in terminal_shim
    assert 'id="sshAuthBannerModal" role="alertdialog"' in template
    assert 'id="sshAuthBannerCancel"' in template
    assert 'id="sshAuthBannerContinue"' in template
    assert "socket.on('ssh_auth_banner'" in app_source
    assert "socket.emit('ssh_auth_banner_decision'" in app_source
    assert "getElementById('sshAuthBannerText').textContent" in app_source
    assert "e.target.id === 'sshAuthBannerModal'" in app_source
