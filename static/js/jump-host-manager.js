/*
 * Jump host (bastion) management: a per-user list of reusable jump hosts the
 * user can pick in the New Connection dialog. Passwords are never stored — when
 * a password-auth jump host is selected, its password is entered at connect time.
 */
window.JumpHostManager = {
    jumpHosts: [],

    load() {
        if (window.socket) {
            window.socket.emit('list_jump_hosts');
        }
    },

    setJumpHosts(list) {
        this.jumpHosts = Array.isArray(list) ? list : [];
        this.renderSelect();
        this.renderList();
    },

    getById(id) {
        return this.jumpHosts.find(j => j.id === id) || null;
    },

    // Fill the New Connection dropdown.
    renderSelect() {
        const select = document.getElementById('jumpHostSelect');
        if (!select) {
            return;
        }
        const current = select.value;
        select.innerHTML = '';
        const none = document.createElement('option');
        none.value = '';
        none.textContent = window.i18n ? i18n.t('connection.noJumpHost') : 'None (direct connection)';
        select.appendChild(none);
        this.jumpHosts.forEach(j => {
            const opt = document.createElement('option');
            opt.value = j.id;
            opt.textContent = `${j.name} (${j.username}@${j.host}:${j.port})`;
            select.appendChild(opt);
        });
        if (current) {
            select.value = current;
        }
        this.updatePasswordVisibility();
    },

    // Show the bastion password field only when the chosen jump host uses password auth.
    updatePasswordVisibility() {
        const select = document.getElementById('jumpHostSelect');
        const group = document.getElementById('jumpHostPasswordGroup');
        if (!select || !group) {
            return;
        }
        const jh = this.getById(select.value);
        group.classList.toggle('hidden', !(jh && jh.auth_type === 'password'));
    },

    // Render the management modal list.
    renderList() {
        const container = document.getElementById('jumpHostsList');
        if (!container) {
            return;
        }
        if (!this.jumpHosts.length) {
            container.innerHTML = `<p class="no-items">${window.i18n ? i18n.t('jumphosts.none') : 'No jump hosts saved'}</p>`;
            return;
        }
        container.innerHTML = '';
        this.jumpHosts.forEach(j => {
            const item = document.createElement('div');
            item.className = 'key-item';

            const info = document.createElement('div');
            info.className = 'key-info';
            const name = document.createElement('strong');
            name.textContent = j.name;
            const addr = document.createElement('span');
            addr.className = 'key-date';
            addr.textContent = `${j.username}@${j.host}:${j.port}`;
            const type = document.createElement('span');
            type.className = 'key-type';
            type.textContent = j.auth_type === 'key'
                ? (window.i18n ? i18n.t('connection.sshKey') : 'SSH Key')
                : (window.i18n ? i18n.t('auth.password') : 'Password');
            info.appendChild(name);
            info.appendChild(addr);
            info.appendChild(type);

            const del = document.createElement('button');
            del.className = 'btn btn-danger btn-sm';
            del.textContent = window.i18n ? i18n.t('common.delete') : 'Delete';
            del.addEventListener('click', () => this.delete(j.id));

            item.appendChild(info);
            item.appendChild(del);
            container.appendChild(item);
        });
    },

    save(name, host, port, username, authType, keyId) {
        if (window.socket) {
            window.socket.emit('save_jump_host', {
                name: name,
                host: host,
                port: parseInt(port) || 22,
                username: username,
                auth_type: authType,
                key_id: authType === 'key' ? keyId : null
            });
        }
    },

    delete(id) {
        const msg = window.i18n ? i18n.t('jumphosts.confirmDelete') : 'Delete this jump host?';
        if (window.confirm(msg) && window.socket) {
            window.socket.emit('delete_jump_host', { jump_host_id: id });
        }
    }
};
