"""Regression checks for the reviewed Socket.IO contract inventory."""
import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOCKET_EVENTS = ROOT / 'app' / 'socket_events.py'
LOGIN_TEMPLATE = ROOT / 'templates' / 'login.html'
BINARY_TRANSFER_CLIENT = ROOT / 'static' / 'js' / 'binary-transfer-client.js'
AUTHENTICATED_TEMPLATE = ROOT / 'templates' / 'index.html'

STALE_SERVER_EVENTS = {'detect_os', 'get_sessions'}
RETAINED_SERVER_EVENTS = {
    'quick_disconnect',
    'list_profiles',
    'save_profile',
    'delete_profile',
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

TRANSFER_CONTROL_EVENTS = {'prepare_transfer', 'cancel_transfer'}


def _event_name(call):
    if not call.args:
        return None
    event = call.args[0]
    return event.value if isinstance(event, ast.Constant) and isinstance(event.value, str) else None


def _server_inventory():
    tree = ast.parse(SOCKET_EVENTS.read_text(encoding='utf-8'))
    handlers = set()
    emitted = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == 'socketio'
            and node.func.attr == 'on'
        ):
            event = _event_name(node)
            if event:
                handlers.add(event)
        if isinstance(node.func, ast.Name) and node.func.id == 'emit':
            event = _event_name(node)
            if event:
                emitted.add(event)
    return handlers, emitted


def _change_password_route():
    tree = ast.parse((ROOT / 'app' / '__init__.py').read_text(encoding='utf-8'))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == 'change_password':
            return node
    raise AssertionError('change_password route not found')


def test_reviewed_stale_server_handlers_are_absent():
    handlers, _ = _server_inventory()

    assert handlers.isdisjoint(STALE_SERVER_EVENTS)


def test_profile_command_set_and_integration_contracts_remain_registered():
    handlers, emitted = _server_inventory()

    assert RETAINED_SERVER_EVENTS <= handlers
    assert RETAINED_RESPONSE_EVENTS <= emitted


def test_transfer_control_contracts_have_client_and_server_halves():
    handlers, _ = _server_inventory()
    client_source = BINARY_TRANSFER_CLIENT.read_text(encoding='utf-8')

    assert TRANSFER_CONTROL_EVENTS <= handlers
    for event in TRANSFER_CONTROL_EVENTS:
        assert f"this.socket.emit('{event}'" in client_source


def test_login_template_has_no_unauthenticated_password_change_action():
    login_template = LOGIN_TEMPLATE.read_text(encoding='utf-8')
    authenticated_template = AUTHENTICATED_TEMPLATE.read_text(encoding='utf-8')
    route = _change_password_route()

    assert "url_for('change_password')" not in login_template
    assert (
        '<button id="changePasswordBtn" class="account-item account-action" '
        'type="button">'
    ) in authenticated_template
    assert any(
        isinstance(decorator, ast.Name) and decorator.id == 'login_required'
        for decorator in route.decorator_list
    )
    assert any(
        isinstance(decorator, ast.Call)
        and isinstance(decorator.func, ast.Attribute)
        and decorator.func.attr == 'route'
        and decorator.args
        and isinstance(decorator.args[0], ast.Constant)
        and decorator.args[0].value == '/change-password'
        for decorator in route.decorator_list
    )
