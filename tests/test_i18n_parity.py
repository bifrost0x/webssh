import re
from pathlib import Path


TERMINOLOGY = {
    'en': ('Quick Connect', 'Hosts'),
    'vi': ('Kết nối nhanh', 'Máy chủ'),
    'de': ('Schnellverbindung', 'Hosts'),
    'fr': ('Connexion rapide', 'Hôtes'),
    'es': ('Conexión rápida', 'Hosts'),
    'zh': ('快速连接', '主机'),
}

LEGACY_CONNECTION_TERMS = {
    'en': r'\bprofiles?\b',
    'vi': r'(?:hồ sơ|cấu hình)',
    'de': r'\bprofil(?:e|en|s)?\b',
    'fr': r'\bprofils?\b',
    'es': r'\bperfiles?\b',
    'zh': r'配置(?:文件)?',
}

SAVED_CONNECTION_COPY_KEYS = {
    'connection.profileUnavailable',
    'connection.loadProfile',
    'connection.selectProfile',
    'connection.saveAsProfile',
    'connection.profileName',
    'profiles.create',
    'profiles.none',
    'profiles.saveFailed',
    'profiles.saved',
    'commandSets.manageHint',
    'commandModes.parametersTooltip',
    'commandSets.legacyNotice',
}


def test_all_locales_have_matching_translation_keys():
    source = Path('static/js/i18n.js').read_text(encoding='utf-8')
    locale_starts = list(re.finditer(r'^    (en|vi|de|fr|es|zh): \{$', source, re.MULTILINE))
    keys_by_locale = {}

    for index, match in enumerate(locale_starts):
        end = locale_starts[index + 1].start() if index + 1 < len(locale_starts) else source.index('\n};', match.end())
        block = source[match.end():end]
        keys_by_locale[match.group(1)] = set(re.findall(r"^        '([^']+)':", block, re.MULTILINE))

    assert set(keys_by_locale) == {'en', 'vi', 'de', 'fr', 'es', 'zh'}
    assert all(
        keys == keys_by_locale['en']
        for keys in keys_by_locale.values()
    )
    assert all(
        'connection.tailscaleSSH' in keys
        for keys in keys_by_locale.values()
    )
    assert all(
        {
            'connection.commandSet',
            'connection.commandSetHint',
            'commandSets.manage',
            'commandSets.create',
            'commandSets.saveToLibrary',
            'commandSets.useSudo',
            'commandSets.useSudoHint',
            'commandSets.sudoBadge',
        } <= keys
        for keys in keys_by_locale.values()
    )
    assert all(
        {
            'profiles.search',
            'profiles.searchPlaceholder',
            'profiles.group',
            'profiles.groupPlaceholder',
            'profiles.favorites',
            'profiles.ungrouped',
            'profiles.favorite',
            'profiles.unfavorite',
            'profiles.noMatches',
        } <= keys
        for keys in keys_by_locale.values()
    )
    assert all(
        {
            'palette.actions',
            'palette.hosts',
            'palette.sessions',
            'palette.savedHost',
            'palette.activeSession',
            'palette.searchPlaceholder',
        } <= keys
        for keys in keys_by_locale.values()
    )
    assert all(
        {
            'keys.addNew',
            'keys.add',
            'keys.rename',
            'keys.renameNamed',
            'keys.saveName',
            'keys.renameFailed',
            'connection.connectBusy',
        } <= keys
        for keys in keys_by_locale.values()
    )


def test_saved_connection_and_quick_connect_terms_are_consistent():
    source = Path('static/js/i18n.js').read_text(encoding='utf-8')
    locale_starts = list(
        re.finditer(r'^    (en|vi|de|fr|es|zh): \{$', source, re.MULTILINE)
    )
    quick_keys = {
        'connection.newConnection',
        'connection.newSSHConnection',
        'shortcuts.newConnection',
    }
    saved_keys = {
        'connection.savedProfiles',
        'profiles.manage',
        'fm.qc.savedProfiles',
    }

    for index, match in enumerate(locale_starts):
        end = (
            locale_starts[index + 1].start()
            if index + 1 < len(locale_starts)
            else source.index('\n};', match.end())
        )
        values = dict(re.findall(
            r"^        '([^']+)': '([^']*)',$",
            source[match.end():end],
            re.MULTILINE,
        ))
        quick_connect, saved_connections = TERMINOLOGY[match.group(1)]
        assert {values[key] for key in quick_keys} == {quick_connect}
        assert {values[key] for key in saved_keys} == {saved_connections}
        assert values['panes.newConnection'] == f'+ {quick_connect}'
        assert values['fm.newConnection'] == f'+ {quick_connect}...'
        assert quick_connect in values['connection.clickToStart']
        assert quick_connect in values['panes.selectSession']
        assert quick_connect in values['panes.assignInfo']
        for key in SAVED_CONNECTION_COPY_KEYS:
            assert not re.search(
                LEGACY_CONNECTION_TERMS[match.group(1)],
                values[key],
                re.IGNORECASE,
            ), f'{match.group(1)}:{key} still uses legacy profile terminology'


def test_new_tab_accessible_name_uses_quick_connect_translation():
    source = Path('templates/index.html').read_text(encoding='utf-8')
    new_tab = re.search(r'<button[^>]+id="newTabBtn"[^>]*>', source)

    assert new_tab is not None
    assert 'title="Quick Connect"' in new_tab.group(0)
    assert 'aria-label="Quick Connect"' in new_tab.group(0)
    assert 'data-i18n-title="connection.newConnection"' in new_tab.group(0)
    assert 'data-i18n-aria-label="connection.newConnection"' in new_tab.group(0)


def test_english_visible_fallbacks_avoid_legacy_connection_terms():
    sources = '\n'.join(
        Path(path).read_text(encoding='utf-8')
        for path in (
            'templates/index.html',
            'static/js/app.js',
            'static/js/profile-manager.js',
            'static/js/sftp-file-manager.js',
        )
    )
    for legacy_text in (
        'Load Profile',
        'Select Profile',
        'Profile Name',
        'Create profile',
        'No profiles saved',
        'Failed to save profile',
        'Profile saved successfully',
        'Profile deleted successfully',
        'delete this profile',
        '+ New Connection...',
        'Saved Profiles',
        'This profile still uses',
        'connection profile',
    ):
        assert legacy_text not in sources


def test_all_locales_preserve_translation_placeholders():
    source = Path('static/js/i18n.js').read_text(encoding='utf-8')
    locale_starts = list(
        re.finditer(r'^    (en|vi|de|fr|es|zh): \{$', source, re.MULTILINE)
    )
    placeholders_by_locale = {}

    for index, match in enumerate(locale_starts):
        end = (
            locale_starts[index + 1].start()
            if index + 1 < len(locale_starts)
            else source.index('\n};', match.end())
        )
        block = source[match.end():end]
        placeholders_by_locale[match.group(1)] = {
            line_match.group(1): set(re.findall(
                r'\{[a-zA-Z][a-zA-Z0-9_]*\}',
                line_match.group(2),
            ))
            for line_match in re.finditer(
                r"^        '([^']+)': (.+),$",
                block,
                re.MULTILINE,
            )
        }

    english = placeholders_by_locale['en']
    assert all(
        placeholders == english
        for placeholders in placeholders_by_locale.values()
    )


def test_english_command_set_copy_explains_execution_boundaries():
    source = Path('static/js/i18n.js').read_text(encoding='utf-8')
    en_start = source.index('    en: {')
    en_end = source.index('\n    vi: {', en_start)
    english_block = source[en_start:en_end]
    match = re.search(
        r"'connection\.commandSetHint': '([^']+)'",
        english_block,
    )

    assert match is not None
    hint = match.group(1).lower()
    assert 'remote host' in hint
    assert 'not in webssh' in hint
    assert 'tmux' in hint
    assert 'not run again' in hint


def test_all_popup_translation_references_exist_in_every_locale():
    i18n_source = Path('static/js/i18n.js').read_text(encoding='utf-8')
    source_paths = sorted(Path('templates').glob('*.html')) + [
        Path('static/js/admin.js'),
        Path('static/js/app.js'),
        Path('static/js/auth.js'),
        Path('static/js/binary-transfer-client.js'),
        Path('static/js/command-library.js'),
        Path('static/js/drag-drop-manager.js'),
        Path('static/js/file-transfer.js'),
        Path('static/js/security-ui.js'),
        Path('static/js/session-diagnostics.js'),
        Path('static/js/settings-center.js'),
        Path('static/js/ssh-error-ui.js'),
        Path('static/js/session-command-launcher.js'),
        Path('static/js/smb-source-dialog.js'),
        Path('static/js/sftp-file-manager.js'),
        Path('static/js/webauthn.js'),
        Path('static/js/webssh2-shell.js'),
    ]
    referenced_keys = set()
    for source_path in source_paths:
        source = source_path.read_text(encoding='utf-8')
        referenced_keys.update(
            re.findall(
                r'data-i18n(?:-placeholder|-title|-label|-aria-label|-alt)?="([^"]+)"',
                source,
            )
        )
        referenced_keys.update(
            re.findall(
                r"(?:i18n\.t|window\.i18n\.t|this\.t|(?<![\w.])t)"
                r"\(\s*'([a-z][a-zA-Z0-9_.-]+)'",
                source,
            )
        )

    locale_starts = list(
        re.finditer(r'^    (en|vi|de|fr|es|zh): \{$', i18n_source, re.MULTILINE)
    )
    missing_by_locale = {}
    for index, match in enumerate(locale_starts):
        end = (
            locale_starts[index + 1].start()
            if index + 1 < len(locale_starts)
            else i18n_source.index('\n};', match.end())
        )
        locale_keys = set(
            re.findall(
                r"^        '([^']+)':",
                i18n_source[match.end():end],
                re.MULTILINE,
            )
        )
        missing = sorted(referenced_keys - locale_keys)
        if missing:
            missing_by_locale[match.group(1)] = missing

    assert missing_by_locale == {}


def test_recent_settings_and_github_surfaces_are_runtime_localized():
    admin_template = Path('templates/admin.html').read_text(encoding='utf-8')
    security_template = Path('templates/security.html').read_text(encoding='utf-8')
    admin_source = Path('static/js/admin.js').read_text(encoding='utf-8')
    settings_source = Path('static/js/settings-center.js').read_text(encoding='utf-8')
    file_manager_source = Path('static/js/sftp-file-manager.js').read_text(
        encoding='utf-8'
    )

    for key in (
        'admin.filterUsers',
        'admin.githubAuthentication',
        'admin.githubSetupFinish',
        'admin.githubSave',
        'settings.center',
        'settings.securityOverview',
        'settings.professionalThemes',
        'security.passkeysAndMfa',
        'security.githubManagedHint',
        'security.manageGithubHint',
    ):
        assert re.search(
            rf'data-i18n(?:-placeholder|-title|-label|-aria-label|-alt)?="{re.escape(key)}"',
            admin_template + security_template,
        )

    assert "t('admin.filteredUserCount'" in admin_source
    assert "'admin.githubSecretStored'" in admin_source
    assert "'admin.githubClearSecretConfirm'" in admin_source
    assert "t('settings.languageUpdated'" in settings_source
    assert "t('settings.savingTheme'" in settings_source
    assert "window.addEventListener('languageChanged', renderMobileSelect)" in settings_source
    assert "window.addEventListener('languageChanged', renderGitHubIdentity)" in Path(
        'static/js/webauthn.js'
    ).read_text(encoding='utf-8')
    assert "window.addEventListener('languageChanged'" in file_manager_source
    assert 'data-i18n-aria-label="fm.workspace.leftSources"' in file_manager_source


def test_popup_inputs_use_explicit_placeholder_translation_attribute():
    source = Path('templates/index.html').read_text(encoding='utf-8')
    popup_source = source[source.index('<div class="modal'):source.index(
        '<script src=',
    )]
    translated_fields = re.findall(
        r'<(?:input|textarea)\b[^>]*\bdata-i18n="[^"]+"[^>]*>',
        popup_source,
    )

    assert translated_fields == []


def test_dynamic_popup_select_placeholders_refresh_with_language():
    profile_source = Path('static/js/profile-manager.js').read_text(encoding='utf-8')
    jump_host_source = Path('static/js/jump-host-manager.js').read_text(encoding='utf-8')

    assert re.search(
        r"this\.t\(\s*'connection\.selectProfile'",
        profile_source,
    )
    assert re.search(
        r"this\.t\(\s*'connection\.selectSSHKey'",
        profile_source,
    )
    assert "window.addEventListener('languageChanged'" in jump_host_source
    assert 'window.JumpHostManager.renderSelect();' in jump_host_source


def test_connection_state_messages_use_the_active_locale():
    source = Path('static/js/app.js').read_text(encoding='utf-8')

    for key in (
        'connection.reconnected',
        'connection.lostReconnecting',
        'connection.lostReconnectingAttempt',
        'connection.disconnectedFromServer',
    ):
        assert f"i18n.t('{key}')" in source


def test_webssh2_pages_use_explicit_placeholder_and_accessible_text_translations():
    source = '\n'.join(
        Path(path).read_text(encoding='utf-8')
        for path in (
            'templates/login.html',
            'templates/register.html',
            'templates/change_password.html',
            'templates/security.html',
        )
    )

    assert not re.search(
        r'<input\b[^>]*\bdata-i18n="[^"]+"[^>]*>',
        source,
    )
    assert 'data-i18n-alt="security.totpQrCode"' in source


def test_admin_authentication_feature_controls_are_fully_translatable():
    template = Path('templates/admin.html').read_text(encoding='utf-8')
    script = '\n'.join(
        Path(path).read_text(encoding='utf-8')
        for path in ('static/js/admin.js', 'static/js/security-ui.js')
    )

    for key in (
        'admin.ldapDirectory',
        'admin.ldapCheckHint',
        'admin.checkConnection',
        'admin.notChecked',
        'admin.authenticationFeatures',
        'admin.authenticationFeaturesHint',
        'admin.featureStatusNotLoaded',
        'admin.directoryUsername',
        'admin.newLocalPasswordAfterUnlinking',
        'admin.unlinkRestoresLocalAuth',
    ):
        assert f'data-i18n="{key}"' in template

    for key in (
        'admin.featureActive',
        'admin.deploymentConfiguration',
        'admin.openSetupGuide',
        'admin.featureStatusLoaded',
        'admin.noAuthenticationFeatures',
        'admin.featureStatusLoading',
    ):
        assert f"'{key}'" in script


def test_workspace_native_controls_are_fully_translatable():
    source = Path('templates/index.html').read_text(encoding='utf-8')

    for key in (
        'workspace.closeBroadcast',
        'workspace.dropFile',
        'workspace.dropDestination',
        'terminal.searchPlaceholder',
        'terminal.searchPrevious',
        'terminal.searchNext',
        'terminal.closeSearch',
        'workspace.activeSessionFiles',
        'sessionCommands.panelLabel',
    ):
        assert key in source


def test_auth_validation_hints_match_the_shared_controller_contract():
    register = Path('templates/register.html').read_text(encoding='utf-8')
    change = Path('templates/change_password.html').read_text(encoding='utf-8')

    for field_id in (
        'registerUsernameHint',
        'registerPasswordHint',
        'registerConfirmHint',
    ):
        assert f'id="{field_id}"' in register
    for field_id in (
        'currentPasswordHint',
        'newPasswordHint',
        'confirmPasswordHint',
    ):
        assert f'id="{field_id}"' in change

    assert 'function toggleLangDropdown()' not in register
    assert 'function toggleLangDropdown()' not in Path(
        'templates/login.html'
    ).read_text(encoding='utf-8')
