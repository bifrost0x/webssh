const ProfileManager = {
    profiles: [],
    keys: [],
    profilesLoaded: false,
    selectedLegacyStartupCommands: '',
    editingProfileId: null,
    editingKeyId: null,
    editingKeyName: null,
    keyRenamePending: false,
    replacingKeyId: null,
    replacementKeyContent: '',
    keyReplacePending: false,
    keyReplaceError: null,
    inlineKeyUploadPending: false,
    profileSearchQuery: '',
    organizationPending: new Set(),

    init() {
        document.getElementById('manageProfilesBtn')?.addEventListener('click', () => {
            window.openConnectionAssetManager?.('hosts');
        });
        document.getElementById('closeProfileManagementModal')?.addEventListener('click', () => {
            window.ModalManager?.close(document.getElementById('profileManagementModal'));
        });
        document.getElementById('newProfileBtn')?.addEventListener('click', () => {
            this.openEditor();
        });
        document.getElementById('profileSearchInput')?.addEventListener('input', event => {
            this.profileSearchQuery = event.target.value;
            this.renderManagementList();
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
            if (button.dataset.profileAction === 'favorite') this.toggleFavorite(profileId);
            if (button.dataset.profileAction === 'edit') this.openEditor(profileId);
            if (button.dataset.profileAction === 'delete') this.deleteProfile(profileId);
        });
        document.getElementById('profileEditorAddKeyBtn')?.addEventListener('click', () => {
            this.setInlineKeyPanelExpanded(true);
            document.getElementById('profileEditorNewKeyName')?.focus();
        });
        document.getElementById('profileEditorCancelKeyBtn')?.addEventListener('click', () => {
            this.setInlineKeyPanelExpanded(false);
        });
        document.getElementById('profileEditorUploadKeyBtn')?.addEventListener('click', () => {
            this.submitInlineKeyUpload();
        });
        document.getElementById('keysList')?.addEventListener('click', event => {
            const button = event.target.closest('[data-key-action]');
            if (!button) return;
            const keyId = button.dataset.keyId;
            if (button.dataset.keyAction === 'rename') this.beginKeyRename(keyId);
            if (button.dataset.keyAction === 'cancel-rename') this.cancelKeyRename();
            if (button.dataset.keyAction === 'save-rename') {
                const input = button.closest('.key-item')?.querySelector('.key-rename-input');
                this.submitKeyRename(keyId, input?.value || '');
            }
            if (button.dataset.keyAction === 'replace') this.beginKeyReplacement(keyId);
            if (button.dataset.keyAction === 'cancel-replace') this.cancelKeyReplacement();
            if (button.dataset.keyAction === 'confirm-replace') {
                const input = button.closest('.key-item')?.querySelector('.key-replace-input');
                this.submitKeyReplacement(keyId, input?.value || '');
            }
            if (button.dataset.keyAction === 'delete') this.deleteKey(keyId);
        });
        document.getElementById('keysList')?.addEventListener('keydown', event => {
            const replacementInput = event.target.closest('.key-replace-input');
            if (replacementInput) {
                if (event.key === 'Escape') {
                    event.preventDefault();
                    event.stopPropagation();
                    this.cancelKeyReplacement();
                }
                if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
                    event.preventDefault();
                    event.stopPropagation();
                    this.submitKeyReplacement(
                        replacementInput.dataset.keyId,
                        replacementInput.value,
                    );
                }
                return;
            }
            const input = event.target.closest('.key-rename-input');
            if (!input) return;
            if (event.key === 'Enter') {
                event.preventDefault();
                event.stopPropagation();
                this.submitKeyRename(input.dataset.keyId, input.value);
            }
            if (event.key === 'Escape') {
                event.preventDefault();
                event.stopPropagation();
                this.cancelKeyRename();
            }
        });
        document.getElementById('keysList')?.addEventListener('input', event => {
            const replacementInput = event.target.closest('.key-replace-input');
            if (replacementInput?.dataset.keyId === this.replacingKeyId) {
                this.replacementKeyContent = replacementInput.value;
                this.keyReplaceError = null;
                return;
            }
            const input = event.target.closest('.key-rename-input');
            if (input?.dataset.keyId === this.editingKeyId) {
                this.editingKeyName = input.value;
            }
        });
        window.addEventListener('languageChanged', () => {
            this.renderProfileSelect();
            this.renderManagementList();
            this.renderKeysList();
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
        if (
            typeof window.dispatchEvent === 'function'
            && typeof window.CustomEvent === 'function'
        ) {
            window.dispatchEvent(new window.CustomEvent('profile-list-change'));
        }
    },

    setKeys(keys) {
        this.keys = Array.isArray(keys) ? keys : [];
        this.renderKeySelect();
        this.renderKeysList();
        this.renderEditorSelects();
        this.refreshEmptyPanes();
    },

    upsertKeySummary(summary) {
        if (!summary || !summary.id) return;
        const exists = this.keys.some(key => key.id === summary.id);
        this.setKeys(exists
            ? this.keys.map(key => key.id === summary.id
                ? {...key, ...summary}
                : key)
            : [...this.keys, summary]);
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
            ? (window.i18n ? i18n.t('connection.savedProfiles') : 'Hosts')
            : (window.i18n ? i18n.t('panes.emptyPane') : 'Empty pane');
        empty.appendChild(title);

        const hint = document.createElement('div');
        hint.className = 'profile-launcher-hint';
        hint.textContent = profiles.length
            ? (window.i18n ? i18n.t('connection.savedProfilesHint') : 'Choose a saved connection to connect')
            : (window.i18n ? i18n.t('panes.selectSession') : 'Select a session or open a connection');
        empty.appendChild(hint);

        if (profiles.length) {
            const search = document.createElement('input');
            search.type = 'search';
            search.className = 'form-control profile-launcher-search';
            search.placeholder = this.t(
                'profiles.searchPlaceholder',
                'Search by name, host, user, or group',
            );
            search.setAttribute(
                'aria-label',
                this.t('profiles.search', 'Search saved connections'),
            );
            const sectionContainer = document.createElement('div');
            sectionContainer.className = 'profile-launcher-sections';

            const createProfileCard = profile => {
                const button = document.createElement('button');
                button.type = 'button';
                button.className = 'profile-launcher-card';
                button.dataset.profileId = profile.id;

                const name = document.createElement('span');
                name.className = 'profile-launcher-name';
                name.textContent = profile.name;
                let favorite = null;
                if (profile.favorite === true) {
                    button.classList.add('is-favorite');
                    favorite = document.createElement('span');
                    favorite.className = 'material-icons profile-launcher-favorite';
                    favorite.setAttribute('aria-hidden', 'true');
                    favorite.textContent = 'star';
                }

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
                if (favorite) button.appendChild(favorite);
                button.addEventListener('click', event => {
                    event.stopPropagation();
                    if (window.launchProfileForPane) {
                        window.launchProfileForPane(profile.id, paneIndex);
                    }
                });
                return button;
            };

            const renderSections = () => {
                sectionContainer.replaceChildren();
                const sections = ProfileLauncherUtils.buildProfileSections(
                    profiles,
                    search.value,
                    {
                        favorites: this.t('profiles.favorites', 'Favorites'),
                        ungrouped: this.t('profiles.ungrouped', 'Ungrouped'),
                    },
                );
                if (!sections.length) {
                    const noMatches = document.createElement('p');
                    noMatches.className = 'no-items';
                    noMatches.textContent = this.t(
                        'profiles.noMatches',
                        'No saved connections match this search.',
                    );
                    sectionContainer.appendChild(noMatches);
                    return;
                }
                sections.forEach(section => {
                    const sectionElement = document.createElement('section');
                    sectionElement.className = 'profile-launcher-section';
                    const heading = document.createElement('h3');
                    heading.className = 'profile-launcher-section-title';
                    heading.textContent = section.label;
                    const list = document.createElement('div');
                    list.className = 'profile-launcher-list';
                    section.profiles.forEach(profile => {
                        list.appendChild(createProfileCard(profile));
                    });
                    sectionElement.append(heading, list);
                    sectionContainer.appendChild(sectionElement);
                });
            };
            search.addEventListener('input', renderSections);
            renderSections();
            empty.append(search, sectionContainer);
        }

        const newConnection = document.createElement('button');
        newConnection.type = 'button';
        newConnection.className = profiles.length
            ? 'btn btn-secondary profile-launcher-new'
            : 'btn btn-primary profile-launcher-new';
        newConnection.textContent = window.i18n
            ? i18n.t('connection.newConnection')
            : 'Quick Connect';
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
            '-- Select Saved Connection --',
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

        container.replaceChildren();
        this.keys.forEach((key, index) => {
            const keyItem = document.createElement('div');
            keyItem.className = 'key-item';
            const replacing = this.replacingKeyId === key.id;
            keyItem.classList.toggle('replacing', replacing);

            const keyInfo = document.createElement('div');
            keyInfo.className = 'key-info';

            if (this.editingKeyId === key.id) {
                const renameEditor = document.createElement('div');
                renameEditor.className = 'key-rename-editor';
                const input = document.createElement('input');
                input.type = 'text';
                input.className = 'form-control key-rename-input';
                input.dataset.keyId = key.id;
                input.value = this.editingKeyName ?? key.name;
                input.maxLength = 128;
                input.disabled = this.keyRenamePending;
                renameEditor.appendChild(input);
                keyInfo.appendChild(renameEditor);
            } else {
                const nameStrong = document.createElement('strong');
                nameStrong.textContent = key.name;
                keyInfo.appendChild(nameStrong);
            }

            const typeSpan = document.createElement('span');
            typeSpan.className = 'key-type';
            typeSpan.textContent = key.key_type;

            const dateSpan = document.createElement('span');
            dateSpan.className = 'key-date';
            dateSpan.textContent = `Uploaded: ${new Date(key.uploaded_at).toLocaleString()}`;

            keyInfo.appendChild(typeSpan);
            keyInfo.appendChild(dateSpan);

            const actions = document.createElement('div');
            actions.className = 'key-item-actions';
            const addAction = (action, label, style) => {
                const button = document.createElement('button');
                button.type = 'button';
                button.className = `btn btn-sm ${style}`;
                button.dataset.keyAction = action;
                button.dataset.keyId = key.id;
                button.textContent = label;
                button.disabled = (
                    this.editingKeyId === key.id && this.keyRenamePending
                ) || (replacing && this.keyReplacePending);
                actions.appendChild(button);
                return button;
            };

            if (this.editingKeyId === key.id) {
                addAction(
                    'save-rename',
                    this.t('keys.saveName', 'Save name'),
                    'btn-primary',
                );
                addAction(
                    'cancel-rename',
                    this.t('common.cancel', 'Cancel'),
                    'btn-secondary',
                );
            } else if (replacing) {
                addAction(
                    'confirm-replace',
                    this.t('keys.replaceConfirm', 'Replace stored key'),
                    'btn-danger',
                );
                addAction(
                    'cancel-replace',
                    this.t('common.cancel', 'Cancel'),
                    'btn-secondary',
                );
            } else {
                const renameButton = addAction(
                    'rename',
                    this.t('keys.rename', 'Rename'),
                    'btn-secondary',
                );
                renameButton.setAttribute(
                    'aria-label',
                    this.t('keys.renameNamed', 'Rename {name}').replace('{name}', key.name),
                );
                const replaceButton = addAction(
                    'replace',
                    this.t('keys.replace', 'Replace'),
                    'btn-secondary',
                );
                replaceButton.setAttribute(
                    'aria-label',
                    this.t('keys.replaceNamed', 'Replace {name}').replace('{name}', key.name),
                );
                addAction('delete', this.t('common.delete', 'Delete'), 'btn-danger');
            }

            keyItem.appendChild(keyInfo);
            keyItem.appendChild(actions);

            if (replacing) {
                const replacementEditor = document.createElement('div');
                replacementEditor.className = 'key-replace-editor';
                const inputId = `key-replacement-${index}`;
                const warningId = `key-replacement-warning-${index}`;
                const statusId = `key-replacement-status-${index}`;

                const warning = document.createElement('p');
                warning.id = warningId;
                warning.className = 'key-replace-warning';
                warning.textContent = this.t(
                    'keys.replaceWarning',
                    'Install the matching public key on every target first. The replacement must be another {type} private key. Future connections using this key will switch immediately; active sessions stay connected.',
                ).replace('{type}', key.key_type);

                const label = document.createElement('label');
                label.htmlFor = inputId;
                label.textContent = this.t(
                    'keys.replacementPrivateKey',
                    'Replacement private key',
                );

                const textarea = document.createElement('textarea');
                textarea.id = inputId;
                textarea.className = 'form-control key-replace-input';
                textarea.dataset.keyId = key.id;
                textarea.rows = 7;
                textarea.maxLength = 64 * 1024;
                textarea.value = this.replacementKeyContent;
                textarea.disabled = this.keyReplacePending;
                textarea.setAttribute('aria-describedby', `${warningId} ${statusId}`);

                const status = document.createElement('div');
                status.id = statusId;
                status.className = 'key-replace-status';
                status.setAttribute('role', 'status');
                status.setAttribute('aria-live', 'polite');
                status.classList.toggle('error', Boolean(this.keyReplaceError));
                status.textContent = this.keyReplacePending
                    ? this.t('keys.replacing', 'Replacing key...')
                    : (this.keyReplaceError || '');

                replacementEditor.append(warning, label, textarea, status);
                keyItem.appendChild(replacementEditor);
            }

            container.appendChild(keyItem);
        });

        if (this.editingKeyId && !this.keyRenamePending) {
            container.querySelector(
                `.key-rename-input[data-key-id="${CSS.escape(this.editingKeyId)}"]`
            )?.focus();
        }
        if (this.replacingKeyId && !this.keyReplacePending) {
            container.querySelector(
                `.key-replace-input[data-key-id="${CSS.escape(this.replacingKeyId)}"]`
            )?.focus();
        }
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
            empty.textContent = this.t('profiles.none', 'No saved connections.');
            container.appendChild(empty);
            return;
        }

        const sections = window.ProfileLauncherUtils?.buildProfileSections(
            this.profiles,
            this.profileSearchQuery,
            {
                favorites: this.t('profiles.favorites', 'Favorites'),
                ungrouped: this.t('profiles.ungrouped', 'Ungrouped'),
            },
        ) || [];
        if (!sections.length) {
            const empty = document.createElement('p');
            empty.className = 'no-items';
            empty.textContent = this.t(
                'profiles.noMatches',
                'No saved connections match this search.',
            );
            container.appendChild(empty);
            return;
        }

        sections.forEach(section => {
            const sectionElement = document.createElement('section');
            sectionElement.className = 'profile-management-section';
            const heading = document.createElement('h3');
            heading.className = 'profile-management-section-title';
            heading.textContent = section.label;
            sectionElement.appendChild(heading);

            section.profiles.forEach(profile => {
                const card = document.createElement('article');
                card.className = 'profile-management-item';
                const info = document.createElement('div');
                info.className = 'profile-management-info';
                const name = document.createElement('strong');
                name.textContent = profile.name;
                if (profile.group) {
                    const group = document.createElement('span');
                    group.className = 'profile-group-badge';
                    group.textContent = profile.group;
                    info.append(name, group);
                } else {
                    info.appendChild(name);
                }
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
                info.append(target, details);

                const actions = document.createElement('div');
                actions.className = 'profile-management-actions';
                const favorite = document.createElement('button');
                favorite.type = 'button';
                favorite.className = 'profile-favorite-button';
                favorite.dataset.profileAction = 'favorite';
                favorite.dataset.profileId = profile.id;
                favorite.disabled = this.organizationPending.has(profile.id);
                favorite.setAttribute('aria-pressed', String(profile.favorite === true));
                const favoriteLabel = this.t(
                    profile.favorite === true ? 'profiles.unfavorite' : 'profiles.favorite',
                    profile.favorite === true
                        ? 'Remove {name} from favorites'
                        : 'Add {name} to favorites',
                ).replace('{name}', profile.name || '');
                favorite.setAttribute('aria-label', favoriteLabel);
                favorite.title = favoriteLabel;
                const star = document.createElement('span');
                star.className = 'material-icons';
                star.setAttribute('aria-hidden', 'true');
                star.textContent = profile.favorite === true ? 'star' : 'star_border';
                favorite.appendChild(star);
                actions.appendChild(favorite);
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
                sectionElement.appendChild(card);
            });
            container.appendChild(sectionElement);
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
        this.setInlineKeyPanelExpanded(false);
        document.getElementById('profileEditorId').value = profile?.id || '';
        document.getElementById('profileEditorName').value = profile?.name || '';
        document.getElementById('profileEditorGroup').value = profile?.group || '';
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
            group: document.getElementById('profileEditorGroup').value.trim(),
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
                    acknowledgement?.error || this.t('profiles.saveFailed', 'Failed to save connection'),
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
        window.launchProfileForPane?.(profileId);
    },

    toggleFavorite(profileId, emit = null) {
        const profile = this.profiles.find(item => item.id === profileId);
        if (!profile || this.organizationPending.has(profileId)) return;
        this.organizationPending.add(profileId);
        this.renderManagementList();
        const send = emit || ((acknowledge) => window.socket?.emit(
            'update_profile_organization',
            {profile_id: profileId, favorite: profile.favorite !== true},
            acknowledge,
        ));
        send(acknowledgement => {
            this.organizationPending.delete(profileId);
            if (!acknowledgement?.success || !acknowledgement.profile) {
                window.showNotification?.(
                    acknowledgement?.error || this.t(
                        'profiles.saveFailed', 'Failed to save connection'
                    ),
                    'error',
                );
                this.renderManagementList();
                return;
            }
            const transientAuthorization = profile.tailscale_authorized;
            this.profiles = this.profiles.map(item => item.id === profileId
                ? {
                    ...acknowledgement.profile,
                    ...(transientAuthorization === undefined
                        ? {}
                        : {tailscale_authorized: transientAuthorization}),
                }
                : item);
            this.renderProfileSelect();
            this.renderManagementList();
            this.refreshEmptyPanes();
        });
    },

    saveProfile(profileData) {
        if (window.socket) {
            window.socket.emit('save_profile', profileData);
        }
    },

    deleteProfile(profileId) {
        if (confirm('Are you sure you want to delete this saved connection?')) {
            if (window.socket) {
                window.socket.emit('delete_profile', { profile_id: profileId });
            }
        }
    },

    setInlineKeyPanelExpanded(expanded) {
        const panel = document.getElementById('profileEditorAddKeyPanel');
        const button = document.getElementById('profileEditorAddKeyBtn');
        panel?.classList.toggle('hidden', !expanded);
        button?.setAttribute('aria-expanded', String(expanded));
        if (!expanded) {
            const status = document.getElementById('profileEditorKeyUploadStatus');
            if (status) {
                status.textContent = '';
                status.classList.remove('error');
            }
        }
    },

    submitInlineKeyUpload() {
        if (this.inlineKeyUploadPending) return;
        const nameInput = document.getElementById('profileEditorNewKeyName');
        const contentInput = document.getElementById('profileEditorNewKeyContent');
        const submitButton = document.getElementById('profileEditorUploadKeyBtn');
        const status = document.getElementById('profileEditorKeyUploadStatus');
        const name = nameInput?.value.trim() || '';
        const keyContent = contentInput?.value || '';
        if (!name || !keyContent) {
            if (status) {
                status.textContent = 'Key name and content are required';
                status.classList.add('error');
            }
            return;
        }

        this.inlineKeyUploadPending = true;
        if (submitButton) submitButton.disabled = true;
        if (status) {
            status.textContent = `${this.t('keys.uploadKey', 'Upload Key')}…`;
            status.classList.remove('error');
        }
        this.uploadKey(name, keyContent, acknowledgement => {
            this.inlineKeyUploadPending = false;
            if (submitButton) submitButton.disabled = false;
            if (!acknowledgement?.success || !acknowledgement.key) {
                if (status) {
                    status.textContent = acknowledgement?.error || 'Failed to upload key';
                    status.classList.add('error');
                }
                return;
            }

            this.upsertKeySummary(acknowledgement.key);
            if (nameInput) nameInput.value = '';
            if (contentInput) contentInput.value = '';
            this.setInlineKeyPanelExpanded(false);
            const select = document.getElementById('profileEditorKeySelect');
            if (select) {
                select.value = acknowledgement.key.id;
                select.focus();
            }
        });
    },

    uploadKey(name, keyContent, callback = null) {
        if (!window.socket) {
            callback?.({success: false, error: 'Connection unavailable'});
            return;
        }
        window.socket.emit('upload_key', {
            name: name,
            key_content: keyContent
        }, acknowledgement => callback?.(acknowledgement));
    },

    beginKeyRename(keyId) {
        if (
            this.keyRenamePending
            || this.replacingKeyId
            || !this.keys.some(key => key.id === keyId)
        ) return;
        this.editingKeyId = keyId;
        this.editingKeyName = this.keys.find(key => key.id === keyId).name;
        this.renderKeysList();
    },

    cancelKeyRename() {
        if (this.keyRenamePending) return;
        this.editingKeyId = null;
        this.editingKeyName = null;
        this.renderKeysList();
    },

    submitKeyRename(keyId, name) {
        if (this.keyRenamePending || keyId !== this.editingKeyId || !window.socket) return;
        this.editingKeyName = name;
        this.keyRenamePending = true;
        this.renderKeysList();
        window.socket.emit('rename_key', {
            key_id: keyId,
            name: name,
        }, acknowledgement => {
            this.keyRenamePending = false;
            if (!acknowledgement?.success || !acknowledgement.key) {
                window.showNotification?.(
                    acknowledgement?.error || this.t(
                        'keys.renameFailed', 'Failed to rename key'
                    ),
                    'error',
                );
                this.renderKeysList();
                return;
            }
            this.editingKeyId = null;
            this.editingKeyName = null;
            this.upsertKeySummary(acknowledgement.key);
        });
    },

    beginKeyReplacement(keyId) {
        if (
            this.keyReplacePending
            || this.editingKeyId
            || !this.keys.some(key => key.id === keyId)
        ) return;
        this.replacingKeyId = keyId;
        this.replacementKeyContent = '';
        this.keyReplaceError = null;
        this.renderKeysList();
    },

    cancelKeyReplacement() {
        if (this.keyReplacePending) return;
        this.replacingKeyId = null;
        this.replacementKeyContent = '';
        this.keyReplaceError = null;
        this.renderKeysList();
    },

    submitKeyReplacement(keyId, keyContent) {
        if (
            this.keyReplacePending
            || keyId !== this.replacingKeyId
            || !window.socket
        ) return;
        this.replacementKeyContent = keyContent;
        if (!keyContent.trim()) {
            this.keyReplaceError = this.t(
                'keys.replacementRequired',
                'Enter the replacement private key.',
            );
            this.renderKeysList();
            return;
        }

        this.keyReplacePending = true;
        this.keyReplaceError = null;
        this.renderKeysList();
        window.socket.emit('replace_key', {
            key_id: keyId,
            key_content: keyContent,
        }, acknowledgement => {
            this.keyReplacePending = false;
            if (!acknowledgement?.success || !acknowledgement.key) {
                this.keyReplaceError = acknowledgement?.error || this.t(
                    'keys.replaceFailed', 'Failed to replace key'
                );
                this.renderKeysList();
                return;
            }
            this.replacingKeyId = null;
            this.replacementKeyContent = '';
            this.keyReplaceError = null;
            this.upsertKeySummary(acknowledgement.key);
        });
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
