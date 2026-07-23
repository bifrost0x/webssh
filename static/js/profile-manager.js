const ProfileManager = {
    profiles: [],
    keys: [],
    profilesLoaded: false,
    selectedLegacyStartupCommands: '',
    editingProfileId: null,

    init() {
        document.getElementById('manageProfilesBtn')?.addEventListener('click', () => {
            this.openManagement();
        });
        document.getElementById('closeProfileManagementModal')?.addEventListener('click', () => {
            window.ModalManager?.close(document.getElementById('profileManagementModal'));
        });
        document.getElementById('newProfileBtn')?.addEventListener('click', () => {
            this.openEditor();
        });
        document.getElementById('cancelProfileEditorBtn')?.addEventListener('click', () => {
            this.showManagementList();
        });
        document.getElementById('profileEditorForm')?.addEventListener('submit', event => {
            event.preventDefault();
            this.saveFromEditor();
        });
        document.getElementById('profileEditorAuthType')?.addEventListener('change', () => {
            this.updateEditorVisibility();
        });
        document.getElementById('profileEditorPostConnectMode')?.addEventListener('change', () => {
            this.updateEditorVisibility();
        });
        document.getElementById('profileEditorUseDefaultParameters')?.addEventListener('change', () => {
            this.updateEditorVisibility();
        });
        [
            'profileEditorCommandSelect',
            'profileEditorCommandSetSelect',
            'profileEditorCommandParameters',
            'profileEditorStartupCommands',
        ].forEach(id => {
            document.getElementById(id)?.addEventListener('input', () => {
                this.renderEditorCommandPreview();
            });
            document.getElementById(id)?.addEventListener('change', () => {
                this.renderEditorCommandPreview();
            });
        });
        document.getElementById('profileManagementList')?.addEventListener('click', event => {
            const button = event.target.closest('[data-profile-action]');
            if (!button) return;
            const profileId = button.dataset.profileId;
            if (button.dataset.profileAction === 'connect') this.connect(profileId);
            if (button.dataset.profileAction === 'edit') this.openEditor(profileId);
            if (button.dataset.profileAction === 'delete') this.deleteProfile(profileId);
        });
        window.addEventListener('languageChanged', () => {
            this.renderProfileSelect();
            this.renderManagementList();
        });
    },

    loadProfiles() {
        if (window.socket) {
            window.socket.emit('list_profiles');
        }
    },

    loadKeys() {
        if (window.socket) {
            window.socket.emit('list_keys');
        }
    },

    setProfiles(profiles) {
        this.profiles = Array.isArray(profiles) ? profiles : [];
        this.profilesLoaded = true;
        this.renderProfileSelect();
        this.renderManagementList();
        this.refreshEmptyPanes();
    },

    setKeys(keys) {
        this.keys = Array.isArray(keys) ? keys : [];
        this.renderKeySelect();
        this.renderKeysList();
        this.renderEditorSelects();
        this.refreshEmptyPanes();
    },

    refreshEmptyPanes() {
        if (typeof SessionManager !== 'undefined') {
            SessionManager.refreshEmptyPanes();
        }
    },

    getProfile(profileId) {
        return this.profiles.find(profile => profile && profile.id === profileId) || null;
    },

    getLaunchMode(profile) {
        return ProfileLauncherUtils.determineLaunchMode(profile, {
            keys: this.keys,
            jumpHosts: window.JumpHostManager?.jumpHosts || [],
        });
    },

    createEmptyPaneContent(paneIndex) {
        const empty = document.createElement('div');
        empty.className = 'pane-empty profile-launcher';

        const icon = document.createElement('div');
        icon.className = 'pane-empty-icon';
        icon.setAttribute('aria-hidden', 'true');
        icon.textContent = '💻';
        empty.appendChild(icon);

        const profiles = this.profilesLoaded ? this.profiles : [];
        const title = document.createElement('div');
        title.className = 'profile-launcher-title';
        title.textContent = profiles.length
            ? (window.i18n ? i18n.t('connection.savedProfiles') : 'Saved Profiles')
            : (window.i18n ? i18n.t('panes.emptyPane') : 'Empty pane');
        empty.appendChild(title);

        const hint = document.createElement('div');
        hint.className = 'profile-launcher-hint';
        hint.textContent = profiles.length
            ? (window.i18n ? i18n.t('connection.savedProfilesHint') : 'Choose a profile to connect')
            : (window.i18n ? i18n.t('panes.selectSession') : 'Select a session or open a connection');
        empty.appendChild(hint);

        if (profiles.length) {
            const list = document.createElement('div');
            list.className = 'profile-launcher-list';
            profiles.forEach(profile => {
                if (!profile || !profile.id) return;

                const button = document.createElement('button');
                button.type = 'button';
                button.className = 'profile-launcher-card';
                button.dataset.profileId = profile.id;

                const name = document.createElement('span');
                name.className = 'profile-launcher-name';
                name.textContent = profile.name;

                const endpoint = document.createElement('span');
                endpoint.className = 'profile-launcher-endpoint';
                endpoint.textContent = ProfileLauncherUtils.formatEndpoint(profile);

                const mode = this.getLaunchMode(profile);
                const action = document.createElement('span');
                action.className = `profile-launcher-action mode-${mode}`;
                action.textContent = mode === 'connect'
                    ? (window.i18n ? i18n.t('connection.connectNow') : 'Connect now')
                    : (mode === 'password' || mode === 'jump-host-password'
                        ? (window.i18n ? i18n.t('connection.passwordRequired') : 'Password required')
                        : (window.i18n ? i18n.t('connection.reviewConnection') : 'Review connection'));

                button.setAttribute(
                    'aria-label',
                    `${String(profile.name || '')}, ${ProfileLauncherUtils.formatEndpoint(profile)}, ${action.textContent}`,
                );
                button.append(name, endpoint, action);
                button.addEventListener('click', event => {
                    event.stopPropagation();
                    if (window.launchProfileForPane) {
                        window.launchProfileForPane(profile.id, paneIndex);
                    }
                });
                list.appendChild(button);
            });
            empty.appendChild(list);
        }

        const newConnection = document.createElement('button');
        newConnection.type = 'button';
        newConnection.className = profiles.length
            ? 'btn btn-secondary profile-launcher-new'
            : 'btn btn-primary profile-launcher-new';
        newConnection.textContent = window.i18n
            ? i18n.t('connection.newConnection')
            : 'New Connection';
        newConnection.addEventListener('click', event => {
            event.stopPropagation();
            window.openConnectionModalForPane?.(paneIndex);
        });
        empty.appendChild(newConnection);
        return empty;
    },

    renderProfileSelect() {
        const select = document.getElementById('profileSelect');
        if (!select) return;

        const current = select.value;
        select.replaceChildren();
        const placeholder = document.createElement('option');
        placeholder.value = '';
        placeholder.textContent = this.t(
            'connection.selectProfile',
            '-- Select Profile --',
        );
        select.appendChild(placeholder);

        this.profiles.forEach(profile => {
            const option = document.createElement('option');
            option.value = profile.id;
            option.textContent = profile.name;
            select.appendChild(option);
        });
        if (current && this.profiles.some(profile => profile.id === current)) {
            select.value = current;
        }
    },

    renderKeySelect() {
        const selects = [
            document.getElementById('keySelect'),
            document.getElementById('jhKeySelect')
        ].filter(Boolean);

        selects.forEach(select => {
            const current = select.value;
            select.replaceChildren();
            const placeholder = document.createElement('option');
            placeholder.value = '';
            placeholder.textContent = this.t(
                'connection.selectSSHKey',
                '-- Select SSH Key --',
            );
            select.appendChild(placeholder);
            this.keys.forEach(key => {
                const option = document.createElement('option');
                option.value = key.id;
                option.textContent = `${key.name} (${key.key_type})`;
                select.appendChild(option);
            });
            if (current) select.value = current;
        });
    },

    renderKeysList() {
        const container = document.getElementById('keysList');
        if (!container) return;

        if (this.keys.length === 0) {
            container.innerHTML = '<p class="no-items">No SSH keys stored</p>';
            return;
        }

        container.innerHTML = '';
        this.keys.forEach(key => {
            const keyItem = document.createElement('div');
            keyItem.className = 'key-item';

            const keyInfo = document.createElement('div');
            keyInfo.className = 'key-info';

            const nameStrong = document.createElement('strong');
            nameStrong.textContent = key.name;

            const typeSpan = document.createElement('span');
            typeSpan.className = 'key-type';
            typeSpan.textContent = key.key_type;

            const dateSpan = document.createElement('span');
            dateSpan.className = 'key-date';
            dateSpan.textContent = `Uploaded: ${new Date(key.uploaded_at).toLocaleString()}`;

            keyInfo.appendChild(nameStrong);
            keyInfo.appendChild(typeSpan);
            keyInfo.appendChild(dateSpan);

            const deleteBtn = document.createElement('button');
            deleteBtn.className = 'btn btn-danger btn-sm';
            deleteBtn.dataset.keyId = key.id;
            deleteBtn.textContent = 'Delete';

            keyItem.appendChild(keyInfo);
            keyItem.appendChild(deleteBtn);

            deleteBtn.addEventListener('click', (e) => {
                const keyId = e.target.dataset.keyId;
                this.deleteKey(keyId);
            });

            container.appendChild(keyItem);
        });
    },

    selectProfile(profileId) {
        const profile = this.profiles.find(p => p.id === profileId);
        if (!profile) return;

        document.getElementById('hostInput').value = profile.host;
        document.getElementById('portInput').value = profile.port;
        document.getElementById('usernameInput').value = profile.username;
        window.ConnectionCommandManager?.applyProfile(profile);
        const legacyNotice = document.getElementById('legacyCommandsNotice');
        const convertButton = document.getElementById('convertLegacyCommandsBtn');
        const hasLegacyCommands = !profile.startup_mode
            && !profile.command_set_id
            && typeof profile.startup_commands === 'string'
            && profile.startup_commands.trim();
        this.selectedLegacyStartupCommands = hasLegacyCommands
            ? profile.startup_commands
            : '';
        legacyNotice?.classList.toggle('hidden', !hasLegacyCommands);
        if (convertButton) {
            convertButton.onclick = hasLegacyCommands
                ? () => CommandSetManager.openLegacyConversion(profile)
                : null;
        }

        document.getElementById('authTypeSelect').value = profile.auth_type;

        this.handleAuthTypeChange(profile.auth_type);

        if (profile.auth_type === 'key' && profile.key_id) {
            document.getElementById('keySelect').value = profile.key_id;
        }

        // Jump host (bastion) reference — the password is entered at connect time.
        const jumpHostSelect = document.getElementById('jumpHostSelect');
        if (jumpHostSelect) {
            jumpHostSelect.value = profile.jump_host_id || '';
            document.getElementById('jumpHostPasswordInput').value = '';
            if (window.JumpHostManager) {
                window.JumpHostManager.updatePasswordVisibility();
            }
        }
    },

    getLegacyStartupCommands() {
        return this.selectedLegacyStartupCommands;
    },

    clearLegacyCommands() {
        this.selectedLegacyStartupCommands = '';
        document.getElementById('legacyCommandsNotice')?.classList.add('hidden');
    },

    handleAuthTypeChange(authType) {
        const passwordGroup = document.getElementById('passwordGroup');
        const keyGroup = document.getElementById('keyGroup');

        if (authType === 'password') {
            passwordGroup.classList.remove('hidden');
            keyGroup.classList.add('hidden');
            document.getElementById('passwordInput').required = true;
            document.getElementById('keySelect').required = false;
        } else if (authType === 'key') {
            passwordGroup.classList.add('hidden');
            keyGroup.classList.remove('hidden');
            document.getElementById('passwordInput').required = false;
            document.getElementById('keySelect').required = true;
        } else {
            passwordGroup.classList.add('hidden');
            keyGroup.classList.add('hidden');
            document.getElementById('passwordInput').required = false;
            document.getElementById('keySelect').required = false;
        }
    },

    t(key, fallback) {
        if (window.i18n) {
            const translated = window.i18n.t(key);
            if (translated && translated !== key) return translated;
        }
        return fallback;
    },

    inferPostConnectMode(profile) {
        return window.ConnectionCommandManager?.inferProfileMode(profile)
            || (profile.command_set_id ? 'command_set'
                : profile.command_id ? 'command'
                    : profile.startup_commands ? 'free_text' : 'none');
    },

    openManagement() {
        this.editingProfileId = null;
        this.showManagementList();
        this.loadProfiles();
        this.loadKeys();
        window.JumpHostManager?.load();
        window.ModalManager?.open(document.getElementById('profileManagementModal'));
    },

    showManagementList() {
        document.getElementById('profileEditorView')?.classList.add('hidden');
        document.getElementById('profileManagementView')?.classList.remove('hidden');
        this.renderManagementList();
    },

    renderManagementList() {
        const container = document.getElementById('profileManagementList');
        if (!container) return;
        container.replaceChildren();
        if (!this.profiles.length) {
            const empty = document.createElement('p');
            empty.className = 'no-items';
            empty.textContent = this.t('profiles.none', 'No profiles saved.');
            container.appendChild(empty);
            return;
        }

        this.profiles.forEach(profile => {
            const card = document.createElement('article');
            card.className = 'profile-management-item';
            const info = document.createElement('div');
            info.className = 'profile-management-info';
            const name = document.createElement('strong');
            name.textContent = profile.name;
            const target = document.createElement('span');
            target.textContent = `${profile.username}@${profile.host}:${profile.port}`;
            const details = document.createElement('span');
            const mode = this.inferPostConnectMode(profile);
            const modeKey = {
                none: 'commandModes.none',
                command_set: 'commandModes.commandSet',
                command: 'commandModes.command',
                free_text: 'commandModes.freeText',
            }[mode];
            let modeLabel = this.t(
                modeKey, mode.replace('_', ' ')
            );
            if (mode === 'command') {
                const command = (window.CommandLibrary?.commands || []).find(
                    item => item.id === profile.command_id
                );
                if (command) modeLabel += `: ${command.name}`;
            }
            if (mode === 'command_set') {
                const commandSet = (window.CommandSetManager?.commandSets || []).find(
                    item => item.id === profile.command_set_id
                );
                if (commandSet) modeLabel += `: ${commandSet.name}`;
            }
            details.textContent = `${profile.auth_type} · ${modeLabel}`;
            info.append(name, target, details);

            const actions = document.createElement('div');
            actions.className = 'profile-management-actions';
            [
                ['connect', this.t('connection.connect', 'Connect'), 'btn-primary'],
                ['edit', this.t('common.edit', 'Edit'), 'btn-secondary'],
                ['delete', this.t('common.delete', 'Delete'), 'btn-danger'],
            ].forEach(([action, label, style]) => {
                const button = document.createElement('button');
                button.type = 'button';
                button.className = `btn btn-sm ${style}`;
                button.dataset.profileAction = action;
                button.dataset.profileId = profile.id;
                button.textContent = label;
                actions.appendChild(button);
            });
            card.append(info, actions);
            container.appendChild(card);
        });
    },

    _fillSelect(select, items, placeholder, labelBuilder) {
        if (!select) return;
        const current = select.value;
        select.replaceChildren();
        const none = document.createElement('option');
        none.value = '';
        none.textContent = placeholder;
        select.appendChild(none);
        items.forEach(item => {
            const option = document.createElement('option');
            option.value = item.id;
            option.textContent = labelBuilder(item);
            select.appendChild(option);
        });
        select.value = current;
    },

    renderEditorSelects() {
        this._fillSelect(
            document.getElementById('profileEditorKeySelect'),
            this.keys,
            this.t('connection.selectSSHKey', 'Select SSH Key'),
            key => `${key.name} (${key.key_type})`,
        );
        this._fillSelect(
            document.getElementById('profileEditorJumpHostSelect'),
            window.JumpHostManager?.jumpHosts || [],
            this.t('connection.noJumpHost', 'None (direct connection)'),
            jump => `${jump.name} (${jump.username}@${jump.host}:${jump.port})`,
        );
        this._fillSelect(
            document.getElementById('profileEditorCommandSelect'),
            window.CommandLibrary?.commands || [],
            this.t('commandModes.selectCommand', 'Select a Command'),
            command => command.name,
        );
        this._fillSelect(
            document.getElementById('profileEditorCommandSetSelect'),
            window.CommandSetManager?.commandSets || [],
            this.t('commandSets.none', 'Select a Command Set'),
            commandSet => commandSet.name,
        );
        this.renderEditorCommandPreview();
    },

    openEditor(profileId = null) {
        const profile = profileId
            ? this.profiles.find(item => item.id === profileId)
            : null;
        if (profileId && !profile) return;
        this.editingProfileId = profile?.id || null;
        this.renderEditorSelects();

        document.getElementById('profileEditorForm')?.reset();
        document.getElementById('profileEditorId').value = profile?.id || '';
        document.getElementById('profileEditorName').value = profile?.name || '';
        document.getElementById('profileEditorHost').value = profile?.host || '';
        document.getElementById('profileEditorPort').value = profile?.port || 22;
        document.getElementById('profileEditorUsername').value = profile?.username || '';
        document.getElementById('profileEditorAuthType').value = profile?.auth_type || 'password';
        document.getElementById('profileEditorKeySelect').value = profile?.key_id || '';
        document.getElementById('profileEditorJumpHostSelect').value = profile?.jump_host_id || '';
        document.getElementById('profileEditorPostConnectMode').value = profile
            ? this.inferPostConnectMode(profile)
            : 'none';
        document.getElementById('profileEditorCommandSelect').value = profile?.command_id || '';
        document.getElementById('profileEditorCommandSetSelect').value = profile?.command_set_id || '';
        document.getElementById('profileEditorStartupCommands').value = profile?.startup_commands || '';

        const hasOverride = Object.prototype.hasOwnProperty.call(
            profile || {}, 'parameters_override'
        );
        document.getElementById('profileEditorUseDefaultParameters').checked = !hasOverride;
        document.getElementById('profileEditorCommandParameters').value = hasOverride
            ? (profile.parameters_override || '')
            : '';

        this.updateEditorVisibility();
        document.getElementById('profileManagementView')?.classList.add('hidden');
        document.getElementById('profileEditorView')?.classList.remove('hidden');
        document.getElementById('profileEditorName')?.focus();
    },

    updateEditorVisibility() {
        const authType = document.getElementById('profileEditorAuthType')?.value;
        document.getElementById('profileEditorKeyGroup')?.classList.toggle(
            'hidden', authType !== 'key'
        );
        const mode = document.getElementById('profileEditorPostConnectMode')?.value || 'none';
        document.getElementById('profileEditorCommandSetGroup')?.classList.toggle(
            'hidden', mode !== 'command_set'
        );
        document.getElementById('profileEditorCommandGroup')?.classList.toggle(
            'hidden', mode !== 'command'
        );
        document.getElementById('profileEditorFreeTextGroup')?.classList.toggle(
            'hidden', mode !== 'free_text'
        );
        const useDefault = document.getElementById('profileEditorUseDefaultParameters');
        const parameterInput = document.getElementById('profileEditorCommandParameters');
        if (parameterInput) parameterInput.disabled = useDefault?.checked !== false;
        this.renderEditorCommandPreview();
    },

    renderEditorCommandPreview() {
        const preview = document.getElementById('profileEditorCommandPreview');
        if (!preview) return;
        const mode = document.getElementById('profileEditorPostConnectMode')?.value || 'none';
        let text = '';
        let error = false;

        if (mode === 'none') {
            text = this.t('commandSets.noSelectionHint', 'No commands will run after connecting.');
        } else if (mode === 'free_text') {
            text = document.getElementById('profileEditorStartupCommands')?.value
                || this.t('commandModes.emptyFreeText', 'Enter at least one command.');
        } else if (mode === 'command') {
            const commandId = document.getElementById('profileEditorCommandSelect')?.value;
            const command = (window.CommandLibrary?.commands || []).find(
                item => item.id === commandId
            );
            if (!command) {
                text = this.t('commandModes.missingCommand', 'Select a command first.');
                error = Boolean(commandId);
            } else {
                const useDefault = document.getElementById(
                    'profileEditorUseDefaultParameters'
                )?.checked !== false;
                const parameters = useDefault
                    ? (command.parameters || '')
                    : (document.getElementById('profileEditorCommandParameters')?.value || '');
                text = command.command + (parameters ? ` ${parameters}` : '');
            }
        } else {
            const commandSetId = document.getElementById(
                'profileEditorCommandSetSelect'
            )?.value;
            const commandSet = (window.CommandSetManager?.commandSets || []).find(
                item => item.id === commandSetId
            );
            if (!commandSet) {
                text = this.t('commandSets.missingSetHint', 'Select a Command Set first.');
                error = Boolean(commandSetId);
            } else if (commandSet.resolution_error) {
                text = commandSet.resolution_error;
                error = true;
            } else {
                text = commandSet.resolved_command || commandSet.steps
                    .map(step => window.CommandSetManager?.stepSummary(step) || '')
                    .join(' && ');
            }
        }

        preview.textContent = text;
        preview.classList.toggle('empty', mode === 'none' || !text);
        preview.classList.toggle('error', error);
    },

    saveFromEditor() {
        if (!window.socket) return;
        const mode = document.getElementById('profileEditorPostConnectMode').value;
        const payload = {
            name: document.getElementById('profileEditorName').value.trim(),
            host: document.getElementById('profileEditorHost').value.trim(),
            port: Number(document.getElementById('profileEditorPort').value) || 22,
            username: document.getElementById('profileEditorUsername').value.trim(),
            auth_type: document.getElementById('profileEditorAuthType').value,
            key_id: document.getElementById('profileEditorKeySelect').value || null,
            jump_host_id: document.getElementById('profileEditorJumpHostSelect').value || null,
            startup_mode: mode,
        };
        if (this.editingProfileId) payload.id = this.editingProfileId;
        if (mode === 'command_set') {
            payload.command_set_id = document.getElementById(
                'profileEditorCommandSetSelect'
            ).value;
        }
        if (mode === 'command') {
            payload.command_id = document.getElementById('profileEditorCommandSelect').value;
            if (!document.getElementById('profileEditorUseDefaultParameters').checked) {
                payload.parameters_override = document.getElementById(
                    'profileEditorCommandParameters'
                ).value;
            }
        }
        if (mode === 'free_text') {
            payload.startup_commands = document.getElementById(
                'profileEditorStartupCommands'
            ).value;
        }

        window.socket.emit('save_profile', payload, acknowledgement => {
            if (!acknowledgement?.success) {
                window.showNotification?.(
                    acknowledgement?.error || this.t('profiles.saveFailed', 'Failed to save profile'),
                    'error',
                );
                return;
            }
            const saved = acknowledgement.profile;
            this.profiles = [
                ...this.profiles.filter(profile => profile.id !== saved.id),
                saved,
            ];
            this.renderProfileSelect();
            this.showManagementList();
        });
    },

    connect(profileId) {
        window.ModalManager?.close(document.getElementById('profileManagementModal'));
        window.openConnectionModalForProfile?.(profileId);
    },

    saveProfile(profileData) {
        if (window.socket) {
            window.socket.emit('save_profile', profileData);
        }
    },

    deleteProfile(profileId) {
        if (confirm('Are you sure you want to delete this profile?')) {
            if (window.socket) {
                window.socket.emit('delete_profile', { profile_id: profileId });
            }
        }
    },

    uploadKey(name, keyContent) {
        if (window.socket) {
            window.socket.emit('upload_key', {
                name: name,
                key_content: keyContent
            });
        }
    },

    deleteKey(keyId) {
        if (confirm('Are you sure you want to delete this SSH key?')) {
            if (window.socket) {
                window.socket.emit('delete_key', { key_id: keyId });
            }
        }
    }
};

window.ProfileManager = ProfileManager;
