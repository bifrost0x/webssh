const ProfileManager = {
    profiles: [],
    keys: [],
    selectedLegacyStartupCommands: '',

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
        this.profiles = profiles;
        this.renderProfileSelect();
    },

    setKeys(keys) {
        this.keys = keys;
        this.renderKeySelect();
        this.renderKeysList();
    },

    renderProfileSelect() {
        const select = document.getElementById('profileSelect');
        if (!select) return;

        select.innerHTML = '<option value="">-- Select Profile --</option>';

        this.profiles.forEach(profile => {
            const option = document.createElement('option');
            option.value = profile.id;
            option.textContent = profile.name;
            select.appendChild(option);
        });
    },

    renderKeySelect() {
        const selects = [
            document.getElementById('keySelect'),
            document.getElementById('jhKeySelect')
        ].filter(Boolean);

        selects.forEach(select => {
            const current = select.value;
            select.innerHTML = '<option value="">-- Select SSH Key --</option>';
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
        if (window.CommandSetManager) {
            CommandSetManager.selectForConnection(profile.command_set_id);
        }
        const legacyNotice = document.getElementById('legacyCommandsNotice');
        const convertButton = document.getElementById('convertLegacyCommandsBtn');
        const hasLegacyCommands = !profile.command_set_id
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
