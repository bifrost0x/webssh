window.SocksProxyManager = {
    socksProxies: [],
    loaded: false,
    editingId: null,
    pending: false,
    unknownOutcome: false,
    baseline: null,

    t(key, fallback) { return window.i18n ? window.i18n.t(key) : fallback; },

    draft() {
        const form = document.getElementById('socksProxyForm');
        return JSON.stringify(Array.from(form?.querySelectorAll('input, select') || [])
            .map(input => ['radio', 'checkbox'].includes(input.type) ? input.checked : input.value));
    },

    isDirty() { return this.baseline !== null && this.draft() !== this.baseline; },

    canDiscard() {
        return !this.pending && (!this.isDirty()
            || window.confirm(this.t('editor.unsavedConfirm', 'Discard unsaved changes?')));
    },

    renderEditorState() {
        const title = document.getElementById('socksProxyEditorTitle');
        const submit = document.querySelector('#saveSocksProxyBtn span');
        const titleKey = this.editingId ? 'socksproxies.edit' : 'socksproxies.addNew';
        const saveKey = this.pending ? 'hostContext.saving' : this.editingId ? 'common.save' : 'socksproxies.add';
        if (title) { title.dataset.i18n = titleKey; title.textContent = this.t(titleKey, 'SOCKS5 Proxy'); }
        if (submit) { submit.dataset.i18n = saveKey; submit.textContent = this.t(saveKey, 'Save'); }
        const status = document.getElementById('spSaveStatus');
        if (status) {
            status.hidden = !this.unknownOutcome;
            status.textContent = this.t('socksproxies.saveUnknownHint', 'Save result unknown. Check the saved list before trying again. Your draft is preserved.');
        }
        const cancel = document.getElementById('cancelSocksProxyEdit');
        if (cancel) { cancel.hidden = !this.editingId && !this.unknownOutcome && !this.isDirty(); cancel.disabled = this.pending; }
        document.querySelectorAll('#socksProxyForm input, #socksProxyForm select').forEach(input => { input.disabled = this.pending; });
        const save = document.getElementById('saveSocksProxyBtn');
        if (save) save.disabled = this.pending || this.unknownOutcome;
    },

    resetEditor() {
        this.editingId = null;
        this.unknownOutcome = false;
        document.getElementById('socksProxyForm')?.reset();
        window.NativeCredentials?.refreshInline?.('spCredential',null);
        this.updateAuthVisibility();
        this.baseline = this.draft();
        this.renderEditorState();
    },

    edit(id) {
        if (!this.canDiscard()) return;
        const host = this.getById(id);
        if (!host) return;
        this.editingId = id;
        this.unknownOutcome = false;
        for (const [field, value] of Object.entries({spNameInput: host.name, spHostInput: host.host,
            spPortInput: host.port, spUsernameInput: host.username})) {
            document.getElementById(field).value = value;
        }
        document.querySelectorAll('input[name="spAuthType"]').forEach(input => { input.checked = input.value === host.auth_type; });
        document.getElementById('spRemoteDns').checked = host.remote_dns !== false;
        this.updateAuthVisibility();
        window.NativeCredentials?.refreshInline?.('spCredential','socks:'+id);
        this.baseline = this.draft();
        this.renderEditorState();
        document.getElementById('socksProxyManagementModal')?.showResourceEditor?.();
        document.getElementById('spNameInput').focus();
    },

    load() {
        if (window.socket) {
            window.socket.emit('list_socks_proxies');
        }
    },

    setSocksProxies(list) {
        this.loaded = true;
        this.socksProxies = Array.isArray(list) ? list : [];
        this.renderSelect();
        this.renderList();
        window.ProfileManager?.renderEditorSelects();
        window.dispatchEvent?.(new CustomEvent('socks-proxy-list-change'));
        if (typeof SessionManager !== 'undefined') {
            SessionManager.refreshEmptyPanes();
        }
    },

    upsertSocksProxy(socksProxy) {
        if (!socksProxy || !socksProxy.id) return;
        this.setSocksProxies(this.socksProxies.some(item => item.id === socksProxy.id)
            ? this.socksProxies.map(item => item.id === socksProxy.id
                ? {...item, ...socksProxy}
                : item)
            : [...this.socksProxies, socksProxy]);
    },

    removeSocksProxy(socksProxyId) {
        if (!socksProxyId) return;
        this.setSocksProxies(this.socksProxies.filter(item => item.id !== socksProxyId));
        if (this.editingId === socksProxyId) this.resetEditor();
    },

    getById(id) {
        return this.socksProxies.find(j => j.id === id) || null;
    },

    selectReference(select, id) {
        if (!select) return;
        if (id && !Array.from(select.options).some(option => option.value === id)) {
            const missing = document.createElement('option');
            missing.value = id;
            missing.textContent = this.t('connection.socksProxyMissing', 'SOCKS5 proxy missing');
            select.appendChild(missing);
        }
        select.value = id || '';
    },

    updateAuthVisibility() {
        const password = document.querySelector('input[name="spAuthType"]:checked')?.value === 'password';
        document.getElementById('spUsernameGroup')?.classList.toggle('hidden', !password);
        const username = document.getElementById('spUsernameInput');
        if (username) username.required = password;
        document.querySelectorAll('[data-socks-password-hint]').forEach(element => { element.hidden = !password; });
        const credentials = document.querySelector('#socksProxyForm .native-host-credentials');
        if (credentials) credentials.classList.toggle('hidden', !password);
    },

    updateRouteControls() {
        for (const prefix of ['', 'profileEditor']) {
            const jump = document.getElementById(prefix ? 'profileEditorJumpHostSelect' : 'jumpHostSelect');
            const socks = document.getElementById(prefix ? 'profileEditorSocksProxySelect' : 'socksProxySelect');
            const auth = document.getElementById(prefix ? 'profileEditorAuthType' : 'authTypeSelect');
            const hint = document.getElementById(prefix ? 'profileEditorRouteHint' : 'connectionRouteHint');
            if (!jump || !socks) continue;
            const tailscale = auth?.value === 'tailscale';
            jump.disabled = tailscale || Boolean(socks.value);
            socks.disabled = tailscale || Boolean(jump.value);
            const key = tailscale ? 'connection.routeTailscale' : jump.value ? 'connection.routeClearJump' : socks.value ? 'connection.routeClearSocks' : '';
            if (hint) { hint.hidden = !key; hint.textContent = key ? this.t(key, '') : ''; }
        }
    },

    // Retain unavailable references: rebuilding a dropdown must never select a direct route.

    renderSelect() {
        const select = document.getElementById('socksProxySelect');
        if (!select) {
            return;
        }
        const current = select.value;
        select.innerHTML = '';
        const none = document.createElement('option');
        none.value = '';
        none.textContent = window.i18n ? i18n.t('connection.socksProxyNone') : 'None';
        select.appendChild(none);
        this.socksProxies.forEach(j => {
            const opt = document.createElement('option');
            opt.value = j.id;
            opt.textContent = `${j.name} (${j.host}:${j.port})`;
            select.appendChild(opt);
        });
        if (current) this.selectReference(select, current);
        this.updatePasswordVisibility();
        this.updateRouteControls();
    },

    // Show the proxy password field only when the chosen SOCKS5 proxy uses password auth.
    updatePasswordVisibility() {
        const select = document.getElementById('socksProxySelect');
        const group = document.getElementById('socksProxyPasswordGroup');
        if (!select || !group) {
            return;
        }
        const sp = this.getById(select.value);
        group.classList.toggle('hidden', !(sp && sp.auth_type === 'password'));
    },

    // Render the management modal list.
    renderList() {
        const container = document.getElementById('socksProxiesList');
        if (!container) {
            return;
        }
        if (!this.loaded) {
            const loading = document.createElement('p'); loading.setAttribute('role', 'status'); loading.textContent = this.t('socksproxies.loading', 'Loading SOCKS5 proxies…'); container.replaceChildren(loading); return;
        }
        if (!this.socksProxies.length) {
            const empty = document.createElement('p');
            empty.className = 'no-items';
            empty.textContent = window.i18n ? i18n.t('socksproxies.none') : 'No SOCKS5 proxys saved';
            const hint = document.createElement('span');
            hint.className = 'empty-state-hint';
            hint.textContent = window.i18n ? i18n.t('socksproxies.emptyHint') : 'Add a SOCKS5 proxy, then choose it in a saved connection.';
            empty.appendChild(hint);
            container.replaceChildren(empty);
            return;
        }
        container.innerHTML = '';
        this.socksProxies.forEach(j => {
            const item = document.createElement('div');
            item.className = 'key-item';

            const info = document.createElement('div');
            info.className = 'key-info';
            const name = document.createElement('strong');
            name.textContent = j.name;
            const addr = document.createElement('span');
            addr.className = 'key-date';
            addr.textContent = `${j.host}:${j.port}`;
            const type = document.createElement('span');
            type.className = 'key-type';
            type.textContent = this.t(j.auth_type === 'password' ? 'socksproxies.login' : 'socksproxies.noLogin', j.auth_type === 'password' ? 'Login' : 'No login');
            info.appendChild(name);
            info.appendChild(addr);
            info.appendChild(type);
            if (j.remote_dns) { const badge = document.createElement('span'); badge.className = 'key-type'; badge.textContent = this.t('socksproxies.remoteDnsBadge', 'Remote DNS'); info.appendChild(badge); }

            const del = document.createElement('button');
            del.className = 'btn btn-danger btn-sm';
            del.textContent = window.i18n ? i18n.t('common.delete') : 'Delete';
            del.addEventListener('click', () => this.delete(j.id));

            item.appendChild(info);
            const actions = document.createElement('div');
            actions.className = 'key-item-actions';
            const edit = document.createElement('button');
            edit.type = 'button';
            edit.className = 'btn btn-secondary btn-sm';
            edit.textContent = this.t('common.edit', 'Edit');
            edit.disabled = this.pending;
            edit.addEventListener('click', () => this.edit(j.id));
            del.type = 'button';
            del.disabled = this.pending;
            actions.append(edit, del);
            item.appendChild(actions);
            container.appendChild(item);
        });
    },

    async save(name, host, port, username, authType, remoteDns) {
        if (this.pending || this.unknownOutcome) return;
        if (!document.getElementById('socksProxyForm')?.reportValidity()) return;
        if (!window.socket?.connected) {
            window.showNotification?.(this.t('notes.offline', 'Offline — not saved'), 'error');
            return;
        }
        const payload = {name, host, port: Number(port), username: authType === 'password' ? username : '', auth_type: authType,
            remote_dns: remoteDns === true};
        if (this.editingId) payload.socks_proxy_id = this.editingId;
        let credential;
        try { credential = authType === 'password' ? window.NativeCredentials?.inlineDraft('spCredential') : null; }
        catch (error) { window.showNotification?.(error.message, 'error'); return; }
        const identity=this.editingId, draft=this.draft();
        const current=()=>this.editingId===identity&&this.draft()===draft&&!document.getElementById('socksProxyManagementModal').hidden&&document.getElementById('socksProxyManagementModal').classList.contains('show');
        const original=this.getById(identity), selected=document.getElementById('spCredentialExisting');
        const changed=original&&['host','port','username','auth_type','remote_dns'].some(key=>String(original[key]||'')!==String(payload[key]||''));
        if(credential?.credential_id&&(changed||selected?.dataset.confirmRequired==='true')){if(!await window.NativeCredentials.confirmTargetReuse(payload)||!current())return;}
        if(credential?.credential_id&&credential.credential_id===selected?.dataset.assigned&&!changed&&selected?.dataset.confirmRequired!=='true')credential=null;
        this.pending = true;
        this.renderEditorState();
        this.renderList();
        if (credential?.password && !this.editingId) {
            try {
                const result = await window.NativeCredentials.mutate('create_for_resource', {resource_kind:'socks', resource:payload, ...credential, username, confirm_target:true}, null, current);
                if (!current()) return;this.upsertSocksProxy(result.resource);this.resetEditor();
            } catch (error) { if (error.name !== 'AbortError') window.showNotification?.(error.message, 'error'); }
            finally { this.pending=false;this.renderEditorState();this.renderList(); }
            return;
        }
        window.socket.timeout(15000).emit('save_socks_proxy', payload, async (error, result) => {
            this.pending = false;
            // A closed or edited form must still leave its disabled pending state.
            try {
            if (error) {
                this.unknownOutcome = true;
                window.showNotification?.(this.t('common.saveUnknownTitle', 'Save outcome unknown'), 'error');
                this.load();
            } else if (!result?.success) {
                window.showNotification?.(result?.error || this.t('socksproxies.saveFailed', 'Could not save the SOCKS5 proxy.'), 'error');
            } else if (result?.success) {
                if (!current()) return;
                this.upsertSocksProxy(result.socks_proxy);
                if (credential) {
                    try { await window.NativeCredentials.mutate(Object.hasOwn(credential,'credential_id')?'assign':'create',{...credential,username,resource_id:'socks:'+result.socks_proxy.id,confirm_target:true,target:{host:payload.host,port:payload.port,username:payload.username,auth_type:payload.auth_type,remote_dns:payload.remote_dns}}, null, current); }
                    catch (error) { if(error.name==='AbortError')return;window.showNotification?.(this.t('credentials.assignmentFailed','Host saved, but password assignment failed. Your password draft is preserved. Review the saved target and try again.'),'error');this.editingId=result.socks_proxy.id;this.renderEditorState();this.renderList();return; }
                }
                if (!current()) return;
                this.resetEditor();
            }
            } finally {
                this.renderEditorState();
                this.renderList();
            }
        });
    },

    handleUsageError(data) {
        const count = /^SOCKS proxy is used by (\d+)/.exec(data?.error || '')?.[1];
        if (!count || !Array.isArray(data.usages)) return false;
        const message = this.t('socksproxies.inUse', 'This SOCKS5 proxy is used by {count} host(s)').replace('{count}', count);
        window.showNotification?.(message + ': ' + data.usages.slice(0, 20).join(', '), 'error');
        return true;
    },

    delete(id) {
        const msg = window.i18n ? i18n.t('socksproxies.confirmDelete') : 'Delete this SOCKS5 proxy?';
        if (this.pending) return;
        if (!window.socket?.connected) {
            window.showNotification?.(this.t('notes.offline', 'Offline — not saved'), 'error');
            return;
        }
        if (id === this.editingId && !this.canDiscard()) return;
        if (window.confirm(msg) && window.socket?.connected) {
            window.socket.emit('delete_socks_proxy', { socks_proxy_id: id }, result => {
                if (result?.success) this.removeSocksProxy(id);

            });
        }
    }
};

window.addEventListener('languageChanged', () => {
    window.SocksProxyManager.renderSelect();
    window.SocksProxyManager.renderList();
    window.SocksProxyManager.renderEditorState();
    window.ProfileManager?.renderEditorSelects();
});

window.addEventListener('DOMContentLoaded', () => {
    const manager = window.SocksProxyManager;
    document.getElementById('socksProxyForm')?.addEventListener('submit', event => {
        event.preventDefault();
        const value = id => document.getElementById(id).value.trim();
        manager.save(value('spNameInput'), value('spHostInput'), value('spPortInput'), value('spUsernameInput'),
            document.querySelector('input[name="spAuthType"]:checked').value, document.getElementById('spRemoteDns').checked);
    });
    document.querySelectorAll('input[name="spAuthType"]').forEach(input => input.addEventListener('change', () => manager.updateAuthVisibility()));
    ['jumpHostSelect', 'socksProxySelect', 'profileEditorJumpHostSelect', 'profileEditorSocksProxySelect', 'authTypeSelect', 'profileEditorAuthType'].forEach(id => {
        document.getElementById(id)?.addEventListener('change', () => manager.updateRouteControls());
    });
    document.getElementById('closeSocksProxyModal')?.addEventListener('click', () => {
        if (!manager.canDiscard()) return;
        const modal = document.getElementById('socksProxyManagementModal');
        if (!window.primaryWorkspaceController?.close(modal)) window.ModalManager?.close(modal);
    });
    manager.updateAuthVisibility();
    manager.baseline = manager.draft();
    document.getElementById('cancelSocksProxyEdit')?.addEventListener('click', () => {
        if (manager.canDiscard()) { manager.resetEditor(); document.getElementById('spNameInput').focus(); }
    });
    document.getElementById('socksProxyForm')?.addEventListener('input', () => manager.renderEditorState());
});
window.addEventListener('beforeunload', event => {
    if (window.SocksProxyManager.isDirty() || window.SocksProxyManager.pending) {
        event.preventDefault();
        event.returnValue = '';
    }
});
