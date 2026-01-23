// Profile Manager - Manages connection profiles
const ProfileManager = {
    profiles: [],
    keys: [],

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

        // Clear existing options except the first one
        select.innerHTML = '<option value="">-- Select Profile --</option>';

        // Add profile options
        this.profiles.forEach(profile => {
            const option = document.createElement('option');
            option.value = profile.id;
            option.textContent = profile.name;
            select.appendChild(option);
        });
    },

    renderKeySelect() {
        const select = document.getElementById('keySelect');
        if (!select) return;

        // Clear existing options except the first one
        select.innerHTML = '<option value="">-- Select SSH Key --</option>';

        // Add key options
        this.keys.forEach(key => {
            const option = document.createElement('option');
            option.value = key.id;
            option.textContent = `${key.name} (${key.key_type})`;
            select.appendChild(option);
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

            // Security Fix: Use DOM methods instead of innerHTML to prevent XSS
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

            // Delete button handler
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

        // Fill connection form
        document.getElementById('hostInput').value = profile.host;
        document.getElementById('portInput').value = profile.port;
        document.getElementById('usernameInput').value = profile.username;

        // Set auth type
        const authTypeRadios = document.querySelectorAll('input[name="authType"]');
        authTypeRadios.forEach(radio => {
            radio.checked = (radio.value === profile.auth_type);
        });

        // Trigger auth type change
        this.handleAuthTypeChange(profile.auth_type);

        // Set key if applicable
        if (profile.auth_type === 'key' && profile.key_id) {
            document.getElementById('keySelect').value = profile.key_id;
        }
    },

    handleAuthTypeChange(authType) {
        const passwordGroup = document.getElementById('passwordGroup');
        const keyGroup = document.getElementById('keyGroup');

        if (authType === 'password') {
            passwordGroup.classList.remove('hidden');
            keyGroup.classList.add('hidden');
            document.getElementById('passwordInput').required = true;
            document.getElementById('keySelect').required = false;
        } else {
            passwordGroup.classList.add('hidden');
            keyGroup.classList.remove('hidden');
            document.getElementById('passwordInput').required = false;
            document.getElementById('keySelect').required = true;
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
