from pathlib import Path


def read(path):
    return Path(path).read_text(encoding='utf-8')


def test_template_has_one_empty_pane_renderer_and_loads_launcher_utility_first():
    template = read('templates/index.html')
    assert 'id="noSessions"' not in template
    assert "filename='js/profile-launcher-utils.js'" in template
    assert "filename='js/connection-launcher.js'" in template
    assert template.index("filename='js/profile-launcher-utils.js'") < template.index(
        "filename='js/connection-launcher.js'"
    )
    assert template.index("filename='js/connection-launcher.js'") < template.index(
        "filename='js/profile-manager.js'"
    )
    assert template.index("filename='js/profile-launcher-utils.js'") < template.index(
        "filename='js/profile-manager.js'"
    )


def test_merged_profile_frontend_assets_have_distinct_cache_versions():
    template = read('templates/index.html')
    expected_versions = {
        "filename='css/style.css'": '?v=12',
        "filename='js/i18n.js'": '?v=9',
        "filename='js/command-workspace.js'": '?v=2',
        "filename='js/command-palette-utils.js'": '?v=1',
        "filename='js/profile-launcher-utils.js'": '?v=5',
        "filename='js/connection-launcher.js'": '?v=1',
        "filename='js/profile-manager.js'": '?v=11',
        "filename='js/session-manager.js'": '?v=6',
        "filename='js/terminal-manager.js'": '?v=4',
        "filename='js/jump-host-manager.js'": '?v=4',
        "filename='js/command-library.js'": '?v=3',
        "filename='js/command-set-manager.js'": '?v=2',
        "filename='js/session-command-launcher.js'": '?v=2',
        "filename='js/app.js'": '?v=11',
    }
    for asset, version in expected_versions.items():
        asset_start = template.index(asset)
        asset_tag = template[asset_start:template.index('>', asset_start)]
        assert version in asset_tag


def test_profile_manager_builds_safe_contextual_launcher_buttons():
    source = read('static/js/profile-manager.js')
    assert 'createEmptyPaneContent(paneIndex)' in source
    assert "button.type = 'button'" in source
    assert 'button.dataset.profileId = profile.id' in source
    assert 'name.textContent = profile.name' in source
    assert 'endpoint.textContent = ProfileLauncherUtils.formatEndpoint(profile)' in source
    assert 'window.launchProfileForPane(profile.id, paneIndex)' in source
    assert 'profile-launcher-card' in source
    assert 'profile-launcher-search' in source
    assert 'profile-launcher-section-title' in source
    assert 'ProfileLauncherUtils.buildProfileSections' in source
    assert 'innerHTML = profile' not in source


def test_profile_dependencies_refresh_only_empty_panes():
    profiles = read('static/js/profile-manager.js')
    jump_hosts = read('static/js/jump-host-manager.js')
    sessions = read('static/js/session-manager.js')
    assert 'SessionManager.refreshEmptyPanes()' in profiles
    assert profiles.count('this.refreshEmptyPanes()') >= 2
    assert 'SessionManager.refreshEmptyPanes()' in jump_hosts
    assert 'refreshEmptyPanes()' in sessions
    assert 'if (!this.paneAssignments[index])' in sessions


def test_dynamic_empty_panes_refresh_after_language_changes():
    source = read('static/js/session-manager.js')
    assert "window.addEventListener('languageChanged'" in source
    assert 'this.refreshEmptyPanes()' in source


def test_launcher_css_is_scrollable_responsive_and_keyboard_visible():
    source = read('static/css/style.css')
    for selector in (
        '.profile-launcher',
        '.profile-launcher-list',
        '.profile-launcher-card',
        '.profile-launcher-card:focus-visible',
    ):
        assert selector in source
    assert 'overflow-y: auto' in source
    assert 'min-height: var(--touch-target-min)' in source


def test_launcher_cards_keep_content_readable_with_many_profiles():
    source = read('static/css/style.css')

    launcher_sections = source[source.index('.profile-launcher-sections {'):source.index(
        '.profile-launcher-section +',
    )]
    launcher_list = source[source.index('.profile-launcher-list {'):source.index(
        '.profile-launcher-card {',
    )]
    endpoint = source[source.index('.profile-launcher-endpoint {'):source.index(
        '.profile-launcher-action {',
    )]

    assert 'width: min(1120px, 100%);' in launcher_sections
    assert (
        'grid-template-columns: repeat(auto-fit, '
        'minmax(min(300px, 100%), 1fr));'
    ) in launcher_list
    assert 'grid-column: 1 / -1;' in endpoint


def test_mobile_launcher_stacks_status_below_profile_details():
    source = read('static/css/style.css')
    mobile_start = source.index(
        '@media (max-width: 767px) {',
        source.index('.profile-launcher-new'),
    )
    mobile_end = source.index('\n}\n\n.terminal-wrapper', mobile_start)
    mobile = source[mobile_start:mobile_end]

    assert 'grid-template-columns: minmax(0, 1fr);' in mobile
    assert '.profile-launcher-action {' in mobile
    assert 'grid-column: 1;' in mobile
    assert 'grid-row: auto;' in mobile
    assert 'justify-self: start;' in mobile


def test_profile_launcher_stylesheet_uses_current_cache_version():
    template = read('templates/index.html')

    assert "filename='css/style.css') }}?v=12" in template


def test_active_session_command_launcher_is_loaded_after_command_data_managers():
    template = read('templates/index.html')
    launcher = "filename='js/session-command-launcher.js'"

    assert launcher in template
    assert template.index("filename='js/command-library.js'") < template.index(launcher)
    assert template.index("filename='js/command-set-manager.js'") < template.index(launcher)
    assert template.index(launcher) < template.index("filename='js/app.js'")


def test_command_palette_loads_safe_model_before_application_code():
    template = read('templates/index.html')

    utility = "filename='js/command-palette-utils.js'"
    application = "filename='js/app.js'"
    assert utility in template
    assert template.index(utility) < template.index(application)
    assert 'data-i18n-placeholder="palette.searchPlaceholder"' in template
    assert 'id="commandPaletteList" role="listbox"' in template


def test_command_palette_uses_safe_rendering_and_existing_activation_paths():
    source = read('static/js/app.js')
    start = source.index('function setupCommandPalette()')
    end = source.index('\n    let openShortcuts', start)
    body = source[start:end]

    assert 'CommandPaletteUtils.buildItems' in body
    assert 'label.textContent = item.label' in body
    assert 'description.textContent = item.description' in body
    assert 'hint.textContent = item.hint' in body
    assert 'window.launchProfileForPane(item.id)' in body
    assert 'SessionManager.switchSession(item.id)' in body
    assert "ProfileManager.profiles.some(profile => profile.id === item.id)" in body
    assert 'SessionManager.sessions[item.id]' in body
    assert 'Object.prototype.hasOwnProperty.call(SessionManager.sessions, item.id)' in body
    assert 'el.innerHTML' not in body
    assert "socket.emit('ssh_connect'" not in body


def test_profile_management_exposes_search_group_and_favorite_controls():
    template = read('templates/index.html')
    source = read('static/js/profile-manager.js')

    assert 'id="profileSearchInput"' in template
    assert 'id="profileEditorGroup"' in template
    assert 'maxlength="64"' in template
    assert "dataset.profileAction = 'favorite'" in source
    assert "'update_profile_organization'" in source
    assert "setAttribute('aria-pressed'" in source


def test_profile_management_uses_precise_ordering_and_custom_group_confirmation():
    template = read('templates/index.html')
    source = read('static/js/profile-manager.js')
    styles = read('static/css/style.css')

    for element_id in (
        'profileMoveConfirmationModal',
        'profileMoveProfileName',
        'profileMoveSourceGroup',
        'cancelProfileMoveBtn',
        'confirmProfileMoveBtn',
    ):
        assert f'id="{element_id}"' in template
    assert "'move_profile'" in source
    assert 'ProfileLauncherUtils?.resolveProfileDrop' in source
    assert "dataset.profileDropIndex" in source
    assert 'confirm_source_group_removal' in source
    assert '.profile-drag-handle' in styles
    assert '.profile-drop-slot.is-active::before' in styles


def test_profile_launch_uses_shared_executor_and_review_callback():
    source = read('static/js/app.js')
    assert 'function startConnection(connectionData, paneIndex)' in source
    assert 'ConnectionLauncher.createConnectionLauncher' in source
    assert 'window.launchProfileForPane = (profileId, paneIndex = null)' in source
    start = source.index('function openProfileForReview')
    end = source.index('const savedConnectionLauncher', start)
    body = source[start:end]
    assert body.index('openConnectionModalForPane(paneIndex)') < body.index(
        'selectConnectionProfile(profileId)'
    )
    assert 'form.requestSubmit()' not in body


def test_auto_launch_has_no_coupled_save_profile_state():
    template = read('templates/index.html')
    source = read('static/js/app.js')
    assert 'saveProfileCheck' not in template
    assert 'profileNameInput' not in template
    assert "socket.emit('save_profile'" not in source


def test_password_modes_focus_the_missing_runtime_secret():
    source = read('static/js/app.js')
    start = source.index('function openProfileForReview')
    end = source.index('const savedConnectionLauncher', start)
    body = source[start:end]
    assert "mode === 'password'" in body
    assert "document.getElementById('passwordInput')" in body
    assert "mode === 'jump-host-password'" in body
    assert "document.getElementById('jumpHostPasswordInput')" in body
    assert '.focus()' in body


def test_submit_keeps_target_pane_until_all_passwords_are_validated():
    source = read('static/js/app.js')
    start = source.index(
        "document.getElementById('connectionForm').addEventListener('submit'"
    )
    end = source.index("document.getElementById('keyUploadForm')", start)
    body = source[start:end]
    assert body.index('const started = startConnection') > body.index(
        "showNotification('Jump host password is required'"
    )
    assert "document.getElementById('passwordInput').focus()" in body
    assert "document.getElementById('jumpHostPasswordInput').focus()" in body


def test_dropdown_and_launcher_share_profile_selection_logic():
    source = read('static/js/app.js')
    assert 'function selectConnectionProfile(profileId)' in source
    change_start = source.index(
        "document.getElementById('profileSelect').addEventListener('change'"
    )
    change_body = source[change_start:change_start + 350]
    assert 'selectConnectionProfile(e.target.value)' in change_body


def test_profile_management_connect_uses_only_the_central_launcher():
    source = read('static/js/profile-manager.js')
    assert 'window.launchProfileForPane?.(profileId)' in source
    assert 'openConnectionModalForProfile' not in source


def test_visible_connection_copy_uses_hosts_and_quick_connect():
    template = read('templates/index.html')
    profiles = read('static/js/profile-manager.js')
    sessions = read('static/js/session-manager.js')
    affected_source = '\n'.join((template, profiles, sessions))

    for obsolete in (
        'Saved Profiles',
        'Choose a profile to connect',
        'New SSH Connection',
        '+ New Connection',
    ):
        assert obsolete not in affected_source

    assert '>Quick Connect<' in template
    assert '>Hosts<' in template
    assert ": 'Quick Connect';" in profiles
    assert ": '+ Quick Connect'," in sessions


def test_quick_connect_hides_optional_connection_features_in_native_details():
    template = read('templates/index.html')
    start = template.index('id="connectionAdvancedSettings"')
    end = template.index('</details>', start)
    advanced = template[start:end]

    assert '<summary' in advanced
    assert 'data-i18n="connection.advancedSettings"' in advanced
    assert 'id="jumpHostSelect"' in advanced
    assert 'class="form-group post-connect-config"' in advanced
    assert 'id="useTmuxCheck"' in advanced
    assert 'id="connectionAdvancedSettings" open' not in template


def test_quick_connect_resets_advanced_state_and_expands_saved_advanced_profiles():
    application = read('static/js/app.js')
    profiles = read('static/js/profile-manager.js')

    assert 'window.setConnectionAdvancedExpanded = expanded =>' in application
    assert 'window.setConnectionAdvancedExpanded(false)' in application
    assert 'ProfileLauncherUtils.usesAdvancedConnectionSettings(profile)' in profiles
    assert 'window.setConnectionAdvancedExpanded?.(' in profiles
    assert 'useTmuxCheck.checked = profile.use_tmux === true' in profiles


def test_profile_groups_render_as_accessible_session_collapsibles():
    source = read('static/js/profile-manager.js')

    assert 'collapsedGroups: new Set()' in source
    assert "dataset.profileGroupToggle = section.key" in source
    assert "setAttribute('aria-expanded', String(!collapsed))" in source
    assert 'items.hidden = collapsed' in source
    assert "event.target.closest('[data-profile-group-toggle]')" in source
    assert 'this.toggleGroupCollapsed(groupToggle.dataset.profileGroupToggle)' in source


def test_profile_groups_support_precise_handle_drag_without_favorite_targets():
    source = read('static/js/profile-manager.js')

    assert "'application/x-webssh-profile-id'" in source
    assert "addEventListener('dragstart'" in source
    assert "addEventListener('dragover'" in source
    assert "addEventListener('drop'" in source
    assert "section.key !== 'favorites'" in source
    assert "dragHandle.dataset.profileDragHandle = ''" in source
    assert 'dragHandle.draggable = canDrag' in source
    assert 'slot.dataset.profileDropGroup = targetGroup' in source
    assert 'slot.dataset.profileDropIndex = String(index)' in source
    assert "'move_profile'" in source
    assert 'confirm_source_group_removal: confirmed === true' in source
    assert "profile.favorite !== true" in source
    assert "this.isProfileSortingEnabled()" in source


def test_advanced_connection_and_group_interactions_have_visible_focus_styles():
    source = read('static/css/style.css')

    assert '.connection-advanced-settings {' in source
    assert '.connection-advanced-settings > summary {' in source
    assert '.connection-advanced-settings > summary:focus-visible' in source
    assert '.profile-management-section-toggle:focus-visible' in source
    assert '.profile-drag-handle:focus-visible' in source
    assert '.profile-drop-slot.is-active::before' in source
    affected_start = source.index('.connection-advanced-settings {')
    affected_end = source.index('.profile-management-section +', affected_start)
    affected = source[affected_start:affected_end]
    assert 'var(--accent-color)' not in affected
    assert 'var(--accent-primary)' in affected
