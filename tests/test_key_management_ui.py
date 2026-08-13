from pathlib import Path


TEMPLATE = Path('templates/index.html').read_text(encoding='utf-8')
PROFILE_MANAGER = Path('static/js/profile-manager.js').read_text(encoding='utf-8')
APP = Path('static/js/app.js').read_text(encoding='utf-8')
STYLE = Path('static/css/style.css').read_text(encoding='utf-8')
I18N = Path('static/js/i18n.js').read_text(encoding='utf-8')


def test_profile_editor_contains_accessible_inline_key_uploader():
    key_group = TEMPLATE[
        TEMPLATE.index('id="profileEditorKeyGroup"'):
        TEMPLATE.index('id="profileEditorJumpHostSelect"')
    ]

    assert 'id="profileEditorAddKeyBtn"' in key_group
    assert 'type="button"' in key_group
    assert 'aria-controls="profileEditorAddKeyPanel"' in key_group
    assert 'aria-expanded="false"' in key_group
    assert 'id="profileEditorAddKeyPanel"' in key_group
    assert 'id="profileEditorNewKeyName"' in key_group
    assert 'id="profileEditorNewKeyContent"' in key_group
    assert 'id="profileEditorKeyUploadStatus"' in key_group
    assert 'role="status"' in key_group
    assert 'aria-live="polite"' in key_group
    assert '<form' not in key_group


def test_key_mutations_use_acknowledgements_and_preserve_local_state():
    for signature in (
        'uploadKey(name, keyContent, callback = null)',
        'beginKeyRename(keyId)',
        'cancelKeyRename()',
        'submitKeyRename(keyId, name)',
        'beginKeyReplacement(keyId)',
        'cancelKeyReplacement()',
        'submitKeyReplacement(keyId, keyContent)',
        'upsertKeySummary(summary)',
    ):
        assert signature in PROFILE_MANAGER

    assert "window.socket.emit('upload_key'" in PROFILE_MANAGER
    assert "window.socket.emit('rename_key'" in PROFILE_MANAGER
    assert "window.socket.emit('replace_key'" in PROFILE_MANAGER
    assert 'this.upsertKeySummary(acknowledgement.key)' in PROFILE_MANAGER
    assert 'profileEditorKeySelect' in PROFILE_MANAGER
    assert 'editingKeyId' in PROFILE_MANAGER
    assert 'editingKeyName' in PROFILE_MANAGER
    assert 'keyRenamePending' in PROFILE_MANAGER
    assert 'inlineKeyUploadPending' in PROFILE_MANAGER
    assert 'replacingKeyId' in PROFILE_MANAGER
    assert 'replacementKeyContent' in PROFILE_MANAGER
    assert 'keyReplacePending' in PROFILE_MANAGER


def test_failed_key_rename_preserves_the_submitted_draft():
    assert 'this.editingKeyName = name;' in PROFILE_MANAGER
    assert 'input.value = this.editingKeyName ?? key.name;' in PROFILE_MANAGER
    failure_branch = PROFILE_MANAGER[
        PROFILE_MANAGER.index('if (!acknowledgement?.success'):
        PROFILE_MANAGER.index('this.editingKeyId = null;', PROFILE_MANAGER.index(
            'if (!acknowledgement?.success'
        ))
    ]
    assert 'this.editingKeyName = null' not in failure_branch


def test_key_list_uses_delegated_actions_and_safe_text_rendering():
    assert "closest('[data-key-action]')" in PROFILE_MANAGER
    assert 'button.dataset.keyAction = action' in PROFILE_MANAGER
    assert "'rename'," in PROFILE_MANAGER
    assert "'save-rename'," in PROFILE_MANAGER
    assert "'cancel-rename'," in PROFILE_MANAGER
    assert "'replace'," in PROFILE_MANAGER
    assert "'confirm-replace'," in PROFILE_MANAGER
    assert "'cancel-replace'," in PROFILE_MANAGER
    assert 'nameStrong.textContent = key.name' in PROFILE_MANAGER
    assert 'innerHTML = key.name' not in PROFILE_MANAGER


def test_key_replacement_ui_is_accessible_warns_and_keeps_secrets_out_of_markup():
    for fragment in (
        "replacementEditor.className = 'key-replace-editor'",
        "textarea.className = 'form-control key-replace-input'",
        "status.setAttribute('role', 'status')",
        "status.setAttribute('aria-live', 'polite')",
        "warning.id = warningId",
        "textarea.setAttribute('aria-describedby', `${warningId} ${statusId}`)",
        "warning.textContent = this.t(",
        "label.textContent = this.t(",
    ):
        assert fragment in PROFILE_MANAGER
    assert 'replacementEditor.innerHTML' not in PROFILE_MANAGER
    assert "'keys.replaceWarning'" in PROFILE_MANAGER
    assert I18N.count("'keys.replaceWarning':") == 6
    assert I18N.count("'keys.replaceConfirm':") == 6
    assert I18N.count("'keys.replaceFailed':") == 6


def test_key_replacement_event_updates_ui_and_asset_version():
    assert "socket.on('key_replaced'" in APP
    assert 'ProfileManager.upsertKeySummary(data.key)' in APP
    assert "filename='js/profile-manager.js') }}?v=11" in TEMPLATE
    assert "filename='js/i18n.js') }}?v=10" in TEMPLATE
    assert "filename='js/app.js') }}?v=12" in TEMPLATE
    assert "filename='css/style.css') }}?v=13" in TEMPLATE


def test_socket_events_refresh_key_ui_without_resetting_profile_editor():
    assert "socket.on('key_renamed'" in APP
    assert 'ProfileManager.upsertKeySummary(data.key)' in APP
    key_uploaded = APP[APP.index("socket.on('key_uploaded'"):APP.index("socket.on('key_deleted'")]
    assert 'profileEditorForm' not in key_uploaded


def test_inline_key_controls_are_responsive():
    for selector in (
        '.profile-inline-key',
        '.key-item-actions',
        '.key-rename-editor',
        '.key-replace-editor',
        '.key-replace-warning',
        '.key-replace-status.error',
        '.profile-inline-key-status.error',
    ):
        assert selector in STYLE
    assert '@media (max-width: 375px)' in STYLE
