"""Structural contracts for the WebSSH application shell."""

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
        b'id="primaryWorkspaceSurface"',
        b'js/primary-workspace-controller.js',
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


def test_workspace_header_uses_the_shipped_webssh_logo(app, client):
    _create_login(app, client)

    response = client.get('/')
    logo = client.get('/static/images/webssh-logo.svg')

    assert response.status_code == 200
    assert b'class="app-brand-logo"' in response.data
    assert b'static/images/webssh-logo.svg' in response.data
    assert logo.status_code == 200
    assert logo.mimetype == 'image/svg+xml'


def test_workspace_renders_the_disconnect_behavior_preference(app, client):
    _create_login(app, client)

    workspace = client.get('/')
    settings = client.get('/settings')

    assert workspace.status_code == 200
    assert settings.status_code == 200
    assert b'data-disconnect-session-action="retry"' in workspace.data
    assert b'id="disconnectSessionActionSelect"' not in workspace.data
    assert b'id="disconnectSessionActionSelect"' in settings.data


def test_saved_connection_editor_renders_tmux_preference_when_enabled(
    app,
    client,
    monkeypatch,
):
    import config

    monkeypatch.setattr(config, 'TMUX_ENABLED', True)
    monkeypatch.setattr(config, 'TMUX_DEFAULT', False)
    _create_login(app, client)

    response = client.get('/')

    assert response.status_code == 200
    assert response.data.count(b'id="useTmuxCheck"') == 1
    assert response.data.count(b'id="profileEditorUseTmux"') == 1
    assert b'id="profileEditorUseTmux" checked' not in response.data


def test_every_user_facing_page_loads_the_shared_webssh2_design_layer(
    app,
    client,
):
    _create_login(app, client)

    for path in ("/", "/security", "/settings", "/change-password"):
        response = client.get(path)
        assert response.status_code == 200
        assert b'css/webssh-2.css' in response.data

    client.post("/logout")
    for path in ("/login", "/register"):
        response = client.get(path)
        assert response.status_code == 200
        assert b'css/webssh-2.css' in response.data


def test_every_user_facing_page_uses_current_shared_asset_versions(app, client):
    _create_login(app, client)

    for path in ("/", "/security", "/settings", "/change-password"):
        response = client.get(path)
        assert response.status_code == 200
        assert b'css/style.css?v=24' in response.data
        assert b'css/webssh-2.css?v=30' in response.data
        assert b'js/i18n.js?v=43' in response.data

    client.post("/logout")
    for path in ("/login", "/register"):
        response = client.get(path)
        assert response.status_code == 200
        assert b'css/style.css?v=24' in response.data
        assert b'css/webssh-2.css?v=30' in response.data
        assert b'js/i18n.js?v=43' in response.data


def test_compact_workspace_controls_keep_accessible_names_and_close_command_input(
    app,
    client,
):
    _create_login(app, client)

    response = client.get('/')

    assert response.status_code == 200
    for marker in (
        b'id="workspaceNavBtn"',
        b'data-i18n-aria-label="navigation.workspaces"',
        b'id="fileTransferBtn"',
        b'data-i18n-aria-label="files.fileManager"',
        b'id="manageProfilesBtn"',
        b'data-i18n-aria-label="connectionAssets.hosts"',
        b'id="commandLibraryBtn"',
        b'data-i18n-aria-label="commands.workspace"',
        b'id="mobileInputCloseBtn"',
        b'data-i18n-aria-label="terminal.hideInput"',
        b'id="mobileSendBtn"',
        b'data-i18n-aria-label="terminal.sendInput"',
        b'js/mobile-app-shell.js?v=7',
    ):
        assert marker in response.data


def test_global_management_navigation_uses_one_primary_workspace_surface(
    app,
    client,
):
    _create_login(app, client)

    response = client.get('/')

    assert response.status_code == 200
    assert b'id="primaryWorkspaceSurface"' in response.data
    assert b'js/primary-workspace-controller.js?v=1' in response.data
    assert b'id="profileManagementModal"' in response.data
    assert b'id="commandWorkspaceModal"' in response.data
    assert b'class="session-tabs-row"' in response.data


def test_hosts_and_commands_share_the_resource_navigation_anatomy(app, client):
    _create_login(app, client)

    response = client.get('/')

    assert response.status_code == 200
    assert response.data.count(b'class="management-resource-title"') >= 4
    assert response.data.count(b'Connection resources') >= 3
    assert b'class="connection-asset-nav-item active"' in response.data


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
            'class="auth-utility-bar"',
            'class="auth-access-dock"',
            'class="auth-context-panel"',
            'class="auth-product-logo"',
            'class="auth-credentials-zone"',
        ):
            assert marker in contents
        assert 'auth-product-version' not in contents
        assert '>2.0<' not in contents

    assert 'class="auth-method-switcher"' in login
    for identity_mode in ('password', 'passkey', 'oidc'):
        assert f'data-auth-mode="{identity_mode}"' in login
    assert 'id="authNotificationContainer"' in login
    assert 'name="webauthn-configured-origin"' in login
    assert 'id="localLoginForm"' in login
    assert 'id="ldapLoginForm"' in login
    assert 'id="loginUsernameHint"' not in login
    assert 'id="loginPasswordHint"' not in login
    assert 'id="registerForm"' in register
    assert "Join us and start your journey" not in register
    assert 'class="auth-context-copy"' in login
    assert 'The control center for your servers.' in login
    assert 'Confirm that it is really you.' in login
    assert 'This password belongs only to your local WebSSH account.' in change_password


def test_authentication_pages_center_the_tagline_with_the_product_logo():
    project_root = Path(__file__).resolve().parents[1]
    pages = (
        project_root / "templates/login.html",
        project_root / "templates/register.html",
        project_root / "templates/change_password.html",
    )

    for page in pages:
        contents = page.read_text(encoding="utf-8")
        lockup_start = contents.index('class="auth-brand-lockup"')
        brand_start = contents.index('class="auth-product-brand"', lockup_start)
        tagline_start = contents.index('class="auth-context-footer"', brand_start)
        lockup_end = contents.index("</div>", tagline_start)

        assert lockup_start < brand_start < tagline_start < lockup_end


def test_auth_brand_lockup_keeps_logo_and_tagline_as_one_centered_unit():
    project_root = Path(__file__).resolve().parents[1]
    css = (project_root / "static/css/webssh-2.css").read_text(encoding="utf-8")
    context_panel = css.split(".auth-context-panel {", 1)[1].split("}", 1)[0]
    lockup = css.split(".auth-brand-lockup {", 1)[1].split("}", 1)[0]
    product_brand = css.split(".auth-product-brand {", 1)[1].split("}", 1)[0]

    assert "justify-content: center;" in context_panel
    assert "gap: clamp(28px, 4dvh, 48px);" in context_panel
    assert "align-content: center;" in lockup
    assert "min-height: 0;" in lockup
    assert "min-height: 0;" in product_brand


def test_auth_context_keeps_readable_dark_surface_tokens_in_light_themes():
    project_root = Path(__file__).resolve().parents[1]
    css = (project_root / "static/css/webssh-2.css").read_text(encoding="utf-8")

    context_panel = css.split(".auth-context-panel {", 1)[1].split("}", 1)[0]
    for token in (
        "--auth-context-text-primary: #f2f6fb;",
        "--auth-context-text-secondary: #c4d0dc;",
        "--auth-context-text-muted: #91a4b7;",
        "--auth-context-accent:",
        "--auth-context-border:",
    ):
        assert token in context_panel

    assert 'body[data-theme="paper"]:has(.auth-access-dock)' in css
    assert "color: var(--auth-context-text-primary);" in css
    assert "color: var(--auth-context-text-muted);" in css


def test_login_and_registration_present_the_webssh_product_workspace():
    project_root = Path(__file__).resolve().parents[1]
    login = (project_root / "templates/login.html").read_text(encoding="utf-8")
    register = (project_root / "templates/register.html").read_text(
        encoding="utf-8"
    )
    css = (project_root / "static/css/webssh-2.css").read_text(encoding="utf-8")

    for contents in (login, register):
        assert 'data-i18n="auth.welcomeToWebssh"' in contents
        assert 'data-i18n="auth.serverControlCenter"' in contents
        assert 'class="auth-product-pillars"' in contents
        for product_area in (
            "ssh-workspaces",
            "file-manager",
            "hosts",
            "commands",
        ):
            assert f'data-product-area="{product_area}"' in contents

    assert 'data-i18n="navigation.sshWorkspaces"' in login
    assert 'data-i18n="navigation.sshWorkspaces"' in register
    assert ".auth-product-pillars" in css
    assert "grid-template-columns: repeat(2, minmax(0, 1fr));" in css
    assert ".auth-access-dock .auth-form-panel .auth-container" in css
    assert "width: 80%;" in css


def test_authentication_shell_scales_on_both_viewport_axes():
    project_root = Path(__file__).resolve().parents[1]
    contents = (project_root / "static/css/webssh-2.css").read_text(
        encoding="utf-8"
    )

    assert "min-height: clamp(560px, 70dvh, 1400px);" in contents
    assert "@media (min-height: 1100px)" in contents
    assert "@media (max-height: 820px)" in contents
    compact = contents[contents.index("@media (max-width: 959px)"):]
    assert "flex: 0 0 auto;" in compact
    assert ".auth-access-dock .auth-form-panel .auth-container" in compact
    assert "width: 100%;" in compact


def test_passkey_login_never_uses_browser_alert():
    project_root = Path(__file__).resolve().parents[1]
    source = (project_root / 'static/js/webauthn.js').read_text(encoding='utf-8')

    assert 'window.alert' not in source

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

    assert "var(--context-workspace-width, 420px)" in contents
    assert ".workspace.layout-desktop.context-open" in contents
    assert ".context-workspace-resizer" in contents
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


def test_security_center_uses_the_same_navigation_grid_as_administration():
    project_root = Path(__file__).resolve().parents[1]
    security = (project_root / "templates/security.html").read_text(encoding="utf-8")
    admin = (project_root / "templates/admin.html").read_text(encoding="utf-8")
    styles = (project_root / "static/css/admin.css").read_text(encoding="utf-8")

    assert 'class="admin-main settings-center-main"' in security
    assert 'class="admin-main"' in admin
    assert 'class="admin-navigation"' in security
    assert 'class="admin-navigation"' in admin
    assert "grid-template-columns: 228px minmax(0, 1fr);" in styles


def test_admin_settings_use_grouped_professional_navigation():
    project_root = Path(__file__).resolve().parents[1]
    contents = (project_root / "templates/admin.html").read_text(
        encoding="utf-8"
    )

    for marker in (
        'class="admin-navigation"',
        'data-settings-section="authentication"',
        'data-settings-panel="authentication"',
        'data-settings-panel="registration"',
        'data-settings-panel="retention"',
        'data-settings-panel="host-trust"',
    ):
        assert marker in contents
