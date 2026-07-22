"""Static integration checks for the command-set user journey."""
import re
from pathlib import Path


def read(path):
    return Path(path).read_text(encoding='utf-8')


def test_connection_form_uses_command_set_selector_and_preview():
    template = read('templates/index.html')

    assert 'id="startupCommandsInput"' not in template
    for element_id in (
        'commandSetSelect',
        'createCommandSetBtn',
        'commandSetPreview',
        'legacyCommandsNotice',
        'convertLegacyCommandsBtn',
    ):
        assert f'id="{element_id}"' in template


def test_account_menu_and_shared_builder_expose_complete_management_flow():
    template = read('templates/index.html')

    assert 'id="manageCommandSetsBtn"' in template
    for element_id in (
        'commandSetManagementModal',
        'commandSetManagementList',
        'newCommandSetBtn',
        'commandSetForm',
        'commandSetNameInput',
        'commandSetDescriptionInput',
        'commandSetSearchInput',
        'commandSetLibraryResults',
        'commandSetSteps',
        'addInlineCommandStepBtn',
        'saveCommandSetBtn',
    ):
        assert f'id="{element_id}"' in template
    assert 'data-os="linux"' in template
    assert 'data-os="windows"' in template


def test_command_set_scripts_load_in_dependency_order_before_app():
    template = read('templates/index.html')

    utils = template.index("filename='js/command-set-utils.js'")
    library = template.index("filename='js/command-library.js'")
    manager = template.index("filename='js/command-set-manager.js'")
    app = template.index("filename='js/app.js'")
    assert utils < library < manager < app


def test_connection_and_profile_payloads_send_only_selected_set_id():
    source = read('static/js/app.js')

    assert "CommandSetManager.getSelectedId()" in source
    assert re.search(r'profilePayload\.command_set_id\s*=\s*commandSetId', source)
    assert re.search(r'connectionData\.command_set_id\s*=\s*commandSetId', source)
    assert 'profilePayload.startup_commands' not in source
    assert re.search(
        r'if \(legacyStartupCommands\) \{\s*'
        r'connectionData\.startup_commands\s*=\s*legacyStartupCommands',
        source,
    )


def test_profile_selection_supports_set_references_and_legacy_conversion():
    source = read('static/js/profile-manager.js')

    assert 'CommandSetManager.selectForConnection(profile.command_set_id)' in source
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


def test_readme_documents_command_set_lifecycle_and_upgrade_behavior():
    readme = read('README.md')

    for phrase in (
        'Create new',
        'Command Sets',
        'Save as library command',
        'maximum 4096 characters',
        'persistent tmux session does not run them again',
        'former free-text startup commands keep',
        'working after an update',
        'cannot be deleted while a profile references it',
        'No additional environment variable, Compose setting',
    ):
        assert phrase in readme
