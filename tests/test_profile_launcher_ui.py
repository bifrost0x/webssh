from pathlib import Path


def read(path):
    return Path(path).read_text(encoding='utf-8')


def test_template_has_one_empty_pane_renderer_and_loads_launcher_utility_first():
    template = read('templates/index.html')
    assert 'id="noSessions"' not in template
    assert "filename='js/profile-launcher-utils.js'" in template
    assert template.index("filename='js/profile-launcher-utils.js'") < template.index(
        "filename='js/profile-manager.js'"
    )


def test_profile_manager_builds_safe_contextual_launcher_buttons():
    source = read('static/js/profile-manager.js')
    assert 'createEmptyPaneContent(paneIndex)' in source
    assert "button.type = 'button'" in source
    assert 'button.dataset.profileId = profile.id' in source
    assert 'name.textContent = profile.name' in source
    assert 'endpoint.textContent = ProfileLauncherUtils.formatEndpoint(profile)' in source
    assert 'window.launchProfileForPane(profile.id, paneIndex)' in source
    assert 'profile-launcher-card' in source
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


def test_profile_launch_prefills_before_requesting_submit():
    source = read('static/js/app.js')
    start = source.index('function launchProfileForPane')
    end = source.index('window.launchProfileForPane', start)
    body = source[start:end]
    assert body.index('openConnectionModalForPane(paneIndex)') < body.index(
        'selectConnectionProfile(profileId)'
    )
    assert body.index('selectConnectionProfile(profileId)') < body.index(
        'form.requestSubmit()'
    )
    assert "mode === 'connect'" in body
    assert 'isSelectedProfileReady(selected)' in body


def test_auto_launch_has_no_coupled_save_profile_state():
    template = read('templates/index.html')
    source = read('static/js/app.js')
    assert 'saveProfileCheck' not in template
    assert 'profileNameInput' not in template
    assert "socket.emit('save_profile'" not in source


def test_password_modes_focus_the_missing_runtime_secret():
    source = read('static/js/app.js')
    start = source.index('function launchProfileForPane')
    end = source.index('window.launchProfileForPane', start)
    body = source[start:end]
    assert "mode === 'password'" in body
    assert "document.getElementById('passwordInput')" in body
    assert "mode === 'jump-host-password'" in body
    assert "document.getElementById('jumpHostPasswordInput')" in body
    assert '.focus()' in body


def test_form_readiness_blocks_stale_auth_key_and_jump_host_state():
    source = read('static/js/app.js')
    assert 'function isSelectedProfileReady(profile)' in source
    assert "authTypeSelect.value !== profile.auth_type" in source
    assert "keySelect.value !== profile.key_id" in source
    assert "jumpHostSelect.value !== (profile.jump_host_id || '')" in source


def test_submit_keeps_target_pane_until_all_passwords_are_validated():
    source = read('static/js/app.js')
    start = source.index(
        "document.getElementById('connectionForm').addEventListener('submit'"
    )
    end = source.index("document.getElementById('keyUploadForm')", start)
    body = source[start:end]
    assert body.index('pendingPaneIndex = null') > body.index(
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
