"""Structural contracts for the WebSSH 2.0 application shell."""

from pathlib import Path


def _create_login(app, client):
    from app.auth import register_user
    from app.models import db

    with app.app_context():
        user, error = register_user("shell_user", "password123")
        assert error is None
        user.is_admin = True
        db.session.commit()
    assert client.post("/login", data={
        "username": "shell_user",
        "password": "password123",
    }).status_code == 302


def test_workspace_exposes_one_context_tab_system_below_connection_tabs(
    app,
    client,
):
    _create_login(app, client)

    response = client.get("/")

    assert response.status_code == 200
    for marker in (
        b'id="globalNavigation"',
        b'id="workspaceNavBtn"',
        b'id="commandLibraryBtn"',
        b'id="contextWorkspace"',
        b'id="contextWorkspaceTabs"',
        b'id="contextWorkspaceLauncher"',
        b'id="contextFilesTab"',
        b'id="contextCommandsTab"',
        b'id="contextDiagnosticsTab"',
        b'id="contextNotesTab"',
        b'id="contextFilesPanel"',
        b'id="contextCommandsPanel"',
        b'id="contextDiagnosticsPanel"',
        b'id="contextNotesPanel"',
        b'id="sessionCommandsPanel"',
        b'id="sessionCommandsMount"',
        b'id="workspaceStatusBar"',
        b'js/workspace-layout-controller.js',
        b'js/webssh2-shell.js',
        b'css/webssh-2.css',
    ):
        assert marker in response.data

    assert b'id="contextWorkspaceTabs" role="tablist"' in response.data
    assert response.data.count(b'data-workspace-context=') == 4
    assert b'aria-controls="contextFilesPanel"' in response.data
    assert b'aria-controls="contextCommandsPanel"' in response.data
    assert b'aria-controls="contextDiagnosticsPanel"' in response.data
    assert b'aria-controls="contextNotesPanel"' in response.data
    assert b'id="sessionSftpToggleBtn"' not in response.data
    assert b'id="sessionCommandsToggle"' not in response.data
    assert b'id="sessionDiagnosticsToggle"' not in response.data
    assert b'id="notepadToggle"' not in response.data
    assert b'id="sessionContextCard"' not in response.data
    assert b'id="sessionToolTabs"' not in response.data


def test_every_user_facing_page_loads_the_shared_webssh2_design_layer(
    app,
    client,
):
    _create_login(app, client)

    for path in ("/", "/security", "/admin", "/change-password"):
        response = client.get(path)
        assert response.status_code == 200
        assert b'css/webssh-2.css' in response.data

    client.post("/logout")
    for path in ("/login", "/register"):
        response = client.get(path)
        assert response.status_code == 200
        assert b'css/webssh-2.css' in response.data


def test_authentication_pages_use_the_shared_professional_auth_shell():
    project_root = Path(__file__).resolve().parents[1]
    login = (project_root / "templates/login.html").read_text(encoding="utf-8")
    register = (project_root / "templates/register.html").read_text(
        encoding="utf-8"
    )
    change_password = (project_root / "templates/change_password.html").read_text(
        encoding="utf-8"
    )

    for contents in (login, register, change_password):
        for marker in (
            'class="auth-shell"',
            'class="auth-shell-header"',
            'class="auth-brand-panel"',
            'class="auth-form-panel"',
        ):
            assert marker in contents

    assert 'class="auth-alternatives"' in login
    assert 'id="localLoginForm"' in login
    assert 'id="ldapLoginForm"' in login
    assert 'id="registerForm"' in register
    assert "Join us and start your journey" not in register

def test_primary_ui_uses_the_vendored_icon_system_instead_of_emoji():
    project_root = Path(__file__).resolve().parents[1]
    sources = [
        *project_root.joinpath("templates").glob("*.html"),
        project_root / "static/js/command-library.js",
        project_root / "static/js/profile-manager.js",
        project_root / "static/js/session-manager.js",
        project_root / "static/js/sftp-file-manager.js",
        project_root / "static/js/auth.js",
        project_root / "static/js/app.js",
        project_root / "static/css/sftp-file-manager.css",
    ]
    forbidden = ("👤", "🔒", "🔑", "👁️", "✨", "🚀", "📡", "➕", "💡", "▶️", "✅", "📋", "✏️", "🗑️", "💻", "🛰️", "📌", "📂", "📁", "🖥️", "✓", "✗", "✎", "⟳")

    for source in sources:
        contents = source.read_text(encoding="utf-8")
        for symbol in forbidden:
            assert symbol not in contents, f"{source.name} still contains emoji {symbol}"


def test_login_loads_the_step_up_dependency_before_webauthn():
    project_root = Path(__file__).resolve().parents[1]
    contents = (project_root / "templates/login.html").read_bytes()

    security_ui = contents.index(b"js/security-ui.js")
    webauthn = contents.index(b"js/webauthn.js")
    assert security_ui < webauthn


def test_context_workspace_has_one_bounded_desktop_panel_and_responsive_sheets():
    project_root = Path(__file__).resolve().parents[1]
    contents = (project_root / "static/css/webssh-2.css").read_text(
        encoding="utf-8"
    )

    assert "clamp(360px, 31vw, 500px)" in contents
    assert ".workspace.layout-desktop.context-open" in contents
    assert ".workspace.layout-tablet .context-workspace" in contents
    assert ".workspace.layout-mobile .context-workspace" in contents
    assert ".context-workspace-tabs" in contents
    assert ".context-workspace-panel" in contents
    assert ".context-workspace .session-diagnostics-overlay" in contents


def test_security_actions_are_grouped_for_predictable_card_alignment():
    project_root = Path(__file__).resolve().parents[1]
    contents = (project_root / "templates/security.html").read_text(
        encoding="utf-8"
    )

    assert contents.count('class="admin-toolbar-actions"') == 2


def test_admin_settings_use_a_balanced_responsive_grid():
    project_root = Path(__file__).resolve().parents[1]
    contents = (project_root / "templates/admin.html").read_text(
        encoding="utf-8"
    )

    for marker in (
        'class="admin-settings-grid"',
        'class="admin-setting-row admin-auth-features"',
        'class="admin-setting-row admin-audit-retention"',
    ):
        assert marker in contents
