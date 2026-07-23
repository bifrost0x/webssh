"""Static integration checks for the command-set user journey."""
import re
from pathlib import Path


def read(path):
    return Path(path).read_text(encoding='utf-8')


def test_connection_form_uses_command_set_selector_and_preview():
    template = read('templates/index.html')

    for element_id in (
        'connectionCommandModeNone',
        'connectionCommandModeSet',
        'connectionCommandModeCommand',
        'connectionCommandModeFreeText',
        'connectionCommandSetPanel',
        'connectionSingleCommandPanel',
        'connectionFreeTextPanel',
        'connectionCommandSelect',
        'connectionCommandParameters',
        'startupCommandsInput',
        'commandSetSelect',
        'manageCommandSetsBtn',
        'editSelectedCommandSetBtn',
        'editSelectedCommandBtn',
        'connectionCommandPreview',
        'legacyCommandsNotice',
        'convertLegacyCommandsBtn',
    ):
        assert f'id="{element_id}"' in template


def test_commands_workspace_unifies_library_and_command_sets():
    template = read('templates/index.html')

    assert 'id="commandSetManagementModal"' not in template
    assert re.search(
        r'id="commandLibraryBtn"[^>]*>\s*'
        r'<span data-i18n="commands\.workspace">',
        template,
    )
    for element_id in (
        'commandWorkspaceModal',
        'closeCommandWorkspaceModal',
        'commandLibraryTab',
        'commandSetsTab',
        'commandLibraryPanel',
        'commandSetsPanel',
        'commandSetManagementList',
        'newCommandSetBtn',
        'commandSetForm',
        'commandSetNameInput',
        'commandSetDescriptionInput',
        'commandSetUseSudoInput',
        'commandSetSearchInput',
        'commandSetLibraryResults',
        'commandSetSteps',
        'addInlineCommandStepBtn',
        'saveCommandSetBtn',
    ):
        assert f'id="{element_id}"' in template
    assert 'role="tablist"' in template
    assert template.count('role="tab"') == 2
    assert template.count('role="tabpanel"') == 2
    assert template.index('id="commandSetsTab"') < template.index('id="commandLibraryTab"')
    assert 'data-os="linux"' in template
    assert 'data-os="windows"' in template


def test_commands_workspace_controller_owns_all_entry_points():
    workspace = read('static/js/command-workspace.js')
    library = read('static/js/command-library.js')
    sets = read('static/js/command-set-manager.js')
    app = read('static/js/app.js')
    template = read('templates/index.html')

    assert "activeSection: 'sets'" in workspace
    assert "open(section = 'sets')" in workspace
    assert "this.select('sets')" in workspace
    assert 'select(section)' in workspace
    assert "CommandWorkspace.open('library')" in library
    assert "CommandWorkspace.open('sets')" in sets
    assert 'openEditor(commandId, returnToModalId = null)' in library
    assert 'CommandWorkspace.init()' in app
    assert "filename='js/command-workspace.js'" in template


def test_command_set_scripts_load_in_dependency_order_before_app():
    template = read('templates/index.html')

    utils = template.index("filename='js/command-set-utils.js'")
    workspace = template.index("filename='js/command-workspace.js'")
    library = template.index("filename='js/command-library.js'")
    manager = template.index("filename='js/command-set-manager.js'")
    connection = template.index("filename='js/connection-command-manager.js'")
    app = template.index("filename='js/app.js'")
    assert utils < workspace < library < manager < connection < app


def test_connection_and_profile_payloads_send_only_selected_set_id():
    source = read('static/js/app.js')

    assert 'ConnectionCommandManager.getPayload()' in source
    assert "window.socket.emit('save_profile'" not in source
    assert 'saveProfileCheck' not in source


def test_profile_selection_supports_set_references_and_legacy_conversion():
    source = read('static/js/profile-manager.js')

    assert 'ConnectionCommandManager?.applyProfile(profile)' in source
    assert 'profile.startup_commands' in source
    assert 'CommandSetManager.openLegacyConversion(profile)' in source
    assert 'getLegacyStartupCommands()' in source


def test_builder_has_search_reorder_parameter_override_and_explicit_promotion():
    source = read('static/js/command-set-manager.js')

    assert 'CommandSetUtils.filterCommands' in source
    assert 'CommandSetUtils.moveStep' in source
    assert "parameters_override" in source
    assert "use-default-parameters" in source
    assert "data.stepAction === 'promote'" in source or "dataset.stepAction === 'promote'" in source
    assert 'showAddCommandForm' in source
    assert "window.socket.emit(event, payload, acknowledgement" in source


def test_command_library_can_return_a_new_command_to_inline_promotion():
    source = read('static/js/command-library.js')

    assert 'pendingSaveCallback' in source
    assert re.search(r'showAddCommandForm\([^)]*options', source)
    assert "window.socket.emit('add_command', data," in source


def test_editing_a_selected_command_returns_to_the_connection_dialog():
    connection_source = read('static/js/connection-command-manager.js')
    library_source = read('static/js/command-library.js')

    assert re.search(
        r"openEditor\(\s*this\.selectedCommandId,\s*'connectionModal'\s*\)",
        connection_source,
    )
    assert 'returnToModalId' in library_source
    assert 'window.ModalManager.activeModal = returnModal' in library_source


def test_command_library_os_filter_does_not_capture_command_set_filters():
    source = read('static/js/command-library.js')

    assert "document.querySelectorAll('#commandLibraryPanel .os-filter-btn')" in source


def test_command_library_search_uses_the_public_i18n_api():
    source = read('static/js/command-library.js')

    assert 'window.i18n.translations' not in source
    assert 'window.i18n.t(categoryKey)' in source


def test_closing_command_set_editor_resets_the_next_management_visit():
    source = read('static/js/command-set-manager.js')

    close_method = re.search(
        r'\n    close\(\) \{(?P<body>.*?)\n    \},',
        source,
        re.DOTALL,
    )
    assert close_method
    assert 'this.showManagementList()' in close_method.group('body')
    assert 'this.returnToConnection = false' in close_method.group('body')


def test_command_set_editor_controls_sudo_defaults_and_payload():
    source = read('static/js/command-set-manager.js')

    assert 'sudoInput.checked = source ? source.use_sudo === true : false' in source
    legacy_conversion = re.search(
        r'openLegacyConversion\(profile\) \{(?P<body>.*?)\n    \},',
        source,
        re.DOTALL,
    )
    assert legacy_conversion
    assert 'sudoInput.checked = false' in legacy_conversion.group('body')
    assert re.search(
        r'use_sudo:\s*document\.getElementById\('
        r"'commandSetUseSudoInput'\)\?\.checked\s*===\s*true",
        source,
    )
    assert 'command-set-sudo-badge' in source


def test_account_menu_owns_profile_key_and_jump_host_management():
    template = read('templates/index.html')

    header_group = re.search(
        r'<div class="header-group"[^>]*>(?P<body>.*?)</div>',
        template,
        re.DOTALL,
    )
    account_menu = re.search(
        r'<div class="account-dropdown-header"[^>]*>(?P<body>.*?)'
        r'<button id="logoutBtn"',
        template,
        re.DOTALL,
    )
    assert header_group
    assert account_menu
    assert 'manageKeysBtn' not in header_group.group('body')
    for element_id in ('manageProfilesBtn', 'manageKeysBtn', 'manageJumpHostsBtn'):
        assert f'id="{element_id}"' in account_menu.group('body')


def test_profile_management_is_independent_from_connect_submit():
    template = read('templates/index.html')
    profile_source = read('static/js/profile-manager.js')

    for element_id in (
        'profileManagementModal',
        'profileManagementList',
        'newProfileBtn',
        'profileEditorForm',
        'profileEditorName',
        'profileEditorHost',
        'profileEditorPort',
        'profileEditorUsername',
        'profileEditorAuthType',
        'profileEditorPostConnectMode',
        'profileEditorCommandSelect',
        'profileEditorCommandSetSelect',
        'profileEditorStartupCommands',
        'profileEditorCommandPreview',
    ):
        assert f'id="{element_id}"' in template
    profile_modal = re.search(
        r'id="profileManagementModal"(?P<body>.*?)</div>\s*</div>\s*</div>',
        template,
        re.DOTALL,
    )
    assert profile_modal
    assert 'type="password"' not in profile_modal.group('body')
    assert "window.socket.emit('save_profile'" in profile_source
    assert "window.socket.emit('ssh_connect'" not in profile_source
    assert 'renderEditorCommandPreview()' in profile_source


def test_connection_mode_help_uses_accessible_tooltips():
    template = read('templates/index.html')

    tooltip_ids = set(re.findall(r'id="([^"]+Tooltip)"[^>]*role="tooltip"', template))
    references = re.findall(r'aria-describedby="([^"]+Tooltip)"', template)
    assert references
    assert set(references).issubset(tooltip_ids)
    assert 'class="info-tooltip-trigger"' in template


def test_readme_documents_command_set_lifecycle_and_upgrade_behavior():
    readme = read('README.md')

    for phrase in (
        'Run after',
        'exact',
        'Free text',
        'Command Sets',
        'Save as library command',
        'maximum 4096 characters',
        'persistent tmux session does not run them again',
        'former free-text startup commands keep',
        'working after an update',
        'cannot be deleted while a profile references it',
        'No additional environment variable, Compose setting',
        'Run commands with sudo',
        'opt-in for new command sets',
        'Existing command sets',
        'legacy conversion keep their saved',
        'does not store or answer a sudo password',
        'created, inspected, updated, or deleted without opening an SSH',
        'joined with `&&`',
        'inside a free-text step remain unchanged',
        'legacy startup commands',
    ):
        assert phrase in readme
