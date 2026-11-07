/*
 * Jump host (bastion) management: a per-user list of reusable jump hosts the
 * user can pick in the New Connection dialog. Password authentication can use
 * an explicitly assigned saved credential or a password entered at connect time.
 */
window.JumpHostManager = {
    jumpHosts: [],
    loaded: false,
    editingId: null,
    pending: false,
    unknownOutcome: false,
    baseline: null,

    t(key, fallback) { return window.i18n ? window.i18n.t(key) : fallback; },

    draft() {
        const form = document.getElementById('jumpHostForm');
        return JSON.stringify(Array.from(form?.querySelectorAll('input, select') || [])
            .map(input => input.type === 'radio' ? input.checked : input.value));
    },

    isDirty() { return this.baseline !== null && this.draft() !== this.baseline; },

    canDiscard() {
        return !this.pending && (!this.isDirty()
            || window.confirm(this.t('editor.unsavedConfirm', 'Discard unsaved changes?')));
    },

    renderEditorState() {
        const title = document.getElementById('jumpHostEditorTitle');
        const submit = document.querySelector('#saveJumpHostBtn span');
        const titleKey = this.editingId ? 'jumphosts.edit' : 'jumphosts.addNew';
        const saveKey = this.pending ? 'hostContext.saving' : this.editingId ? 'common.save' : 'jumphosts.add';
        if (title) { title.dataset.i18n = titleKey; title.textContent = this.t(titleKey, 'Jump Host'); }
        if (submit) { submit.dataset.i18n = saveKey; submit.textContent = this.t(saveKey, 'Save'); }
        const status = document.getElementById('jhSaveStatus');
        if (status) {
            status.hidden = !this.unknownOutcome;
            status.textContent = this.t('jumphosts.saveUnknownHint', 'Save result unknown. Check the saved list before trying again. Your draft is preserved.');
        }
        const cancel = document.getElementById('cancelJumpHostEdit');
        if (cancel) { cancel.hidden = !this.editingId && !this.unknownOutcome && !this.isDirty(); cancel.disabled = this.pending; }
        document.querySelectorAll('#jumpHostForm input, #jumpHostForm select').forEach(input => { input.disabled = this.pending; });
        const save = document.getElementById('saveJumpHostBtn');
        if (save) save.disabled = this.pending || this.unknownOutcome;
    },

    resetEditor() {
        this.editingId = null;
        this.unknownOutcome = false;
        document.getElementById('jumpHostForm')?.reset();
        window.NativeCredentials?.refreshInline?.('jhCredential',null);
        document.getElementById('jhKeyGroup')?.classList.add('hidden');
        this.baseline = this.draft();
        this.renderEditorState();
    },

    edit(id) {
        if (!this.canDiscard()) return;
        const host = this.getById(id);
        if (!host) return;
        this.editingId = id;
        this.unknownOutcome = false;
        for (const [field, value] of Object.entries({jhNameInput: host.name, jhHostInput: host.host,
            jhPortInput: host.port, jhUsernameInput: host.username, jhKeySelect: host.key_id || ''})) {
            document.getElementById(field).value = value;
        }
        document.querySelectorAll('input[name="jhAuthType"]').forEach(input => { input.checked = input.value === host.auth_type; });
        document.getElementById('jhKeyGroup').classList.toggle('hidden', host.auth_type !== 'key');
        window.NativeCredentials?.refreshInline?.('jhCredential','jump:'+id);
        this.baseline = this.draft();
        this.renderEditorState();
        document.getElementById('jumpHostManagementModal')?.showResourceEditor?.();
        document.getElementById('jhNameInput').focus();
    },

    load() {
        if (window.socket) {
            window.socket.emit('list_jump_hosts');
        }
    },

    setJumpHosts(list) {
        this.loaded = true;
        this.jumpHosts = Array.isArray(list) ? list : [];
        this.renderSelect();
        this.renderList();
        window.ProfileManager?.renderEditorSelects();
        window.dispatchEvent?.(new CustomEvent('jump-host-list-change'));
        if (typeof SessionManager !== 'undefined') {
            SessionManager.refreshEmptyPanes();
        }
    },

    upsertJumpHost(jumpHost) {
        if (!jumpHost || !jumpHost.id) return;
        this.setJumpHosts(this.jumpHosts.some(item => item.id === jumpHost.id)
            ? this.jumpHosts.map(item => item.id === jumpHost.id
                ? {...item, ...jumpHost}
                : item)
            : [...this.jumpHosts, jumpHost]);
    },

    removeJumpHost(jumpHostId) {
        if (!jumpHostId) return;
        this.setJumpHosts(this.jumpHosts.filter(item => item.id !== jumpHostId));
        if (this.editingId === jumpHostId) this.resetEditor();
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
            const empty = document.createElement('p');
            empty.className = 'no-items';
            empty.textContent = window.i18n ? i18n.t('jumphosts.none') : 'No jump hosts saved';
            const hint = document.createElement('span');
            hint.className = 'empty-state-hint';
            hint.textContent = window.i18n ? i18n.t('empty.jumpsHint') : 'Add a jump host, then choose it in a saved connection.';
            empty.appendChild(hint);
            container.replaceChildren(empty);
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
                ? (window.i18n ? i18n.t('fm.qc.sshKey') : 'SSH Key')
                : (window.i18n ? i18n.t('auth.password') : 'Password');
            info.appendChild(name);
            info.appendChild(addr);
            info.appendChild(type);

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

    async save(name, host, port, username, authType, keyId) {
        if (this.pending || this.unknownOutcome) return;
        if (!window.socket?.connected) {
            window.showNotification?.(this.t('notes.offline', 'Offline — not saved'), 'error');
            return;
        }
        const payload = {name, host, port: Number(port), username, auth_type: authType,
            key_id: authType === 'key' ? keyId : null};
        if (this.editingId) payload.jump_host_id = this.editingId;
        let credential;
        try { credential = authType === 'password' ? window.NativeCredentials?.inlineDraft('jhCredential') : null; }
        catch (error) { window.showNotification?.(error.message, 'error'); return; }
        const identity=this.editingId, draft=this.draft();
        const current=()=>this.editingId===identity&&this.draft()===draft&&!document.getElementById('jumpHostManagementModal').hidden&&document.getElementById('jumpHostManagementModal').classList.contains('show');
        const original=this.getById(identity), selected=document.getElementById('jhCredentialExisting');
        const changed=original&&['host','port','username','auth_type','key_id'].some(key=>String(original[key]||'')!==String(payload[key]||''));
        if(credential?.credential_id&&(changed||selected?.dataset.confirmRequired==='true')){if(!await window.NativeCredentials.confirmTargetReuse(payload)||!current())return;}
        if(credential?.credential_id&&credential.credential_id===selected?.dataset.assigned&&!changed&&selected?.dataset.confirmRequired!=='true')credential=null;
        this.pending = true;
        this.renderEditorState();
        this.renderList();
        if (credential?.password && !this.editingId) {
            try {
                const result = await window.NativeCredentials.mutate('create_for_resource', {resource_kind:'jump', resource:payload, ...credential, username, confirm_target:true}, null, current);
                if (!current()) return;this.upsertJumpHost(result.resource);this.resetEditor();
            } catch (error) { if (error.name !== 'AbortError') window.showNotification?.(error.message, 'error'); }
            finally { this.pending=false;this.renderEditorState();this.renderList(); }
            return;
        }
        window.socket.timeout(15000).emit('save_jump_host', payload, async (error, result) => {
            this.pending = false;
            if (error) {
                this.unknownOutcome = true;
                window.showNotification?.(this.t('common.saveUnknownTitle', 'Save outcome unknown'), 'error');
                this.load();
            } else if (result?.success) {
                if (!current()) return;
                this.upsertJumpHost(result.jump_host);
                if (credential) {
                    try { await window.NativeCredentials.mutate(Object.hasOwn(credential,'credential_id')?'assign':'create',{...credential,username,resource_id:'jump:'+result.jump_host.id,confirm_target:true,target:{host:payload.host,port:payload.port,username:payload.username,auth_type:payload.auth_type,key_id:payload.key_id}}, null, current); }
                    catch (error) { if(error.name==='AbortError')return;window.showNotification?.(this.t('credentials.assignmentFailed','Host saved, but password assignment failed. Your password draft is preserved. Review the saved target and try again.'),'error');this.editingId=result.jump_host.id;this.renderEditorState();this.renderList();return; }
                }
                if (!current()) return;
                this.resetEditor();
            }
            this.renderEditorState();
            this.renderList();
        });
    },

    delete(id) {
        const msg = window.i18n ? i18n.t('jumphosts.confirmDelete') : 'Delete this jump host?';
        if (this.pending) return;
        if (!window.socket?.connected) {
            window.showNotification?.(this.t('notes.offline', 'Offline — not saved'), 'error');
            return;
        }
        if (id === this.editingId && !this.canDiscard()) return;
        if (window.confirm(msg) && window.socket?.connected) {
            window.socket.emit('delete_jump_host', { jump_host_id: id });
        }
    }
};

window.addEventListener('languageChanged', () => {
    window.JumpHostManager.renderSelect();
    window.JumpHostManager.renderList();
    window.JumpHostManager.renderEditorState();
    window.ProfileManager?.renderEditorSelects();
});

window.addEventListener('DOMContentLoaded', () => {
    const manager = window.JumpHostManager;
    manager.baseline = manager.draft();
    document.getElementById('cancelJumpHostEdit')?.addEventListener('click', () => {
        if (manager.canDiscard()) { manager.resetEditor(); document.getElementById('jhNameInput').focus(); }
    });
    document.getElementById('jumpHostForm')?.addEventListener('input', () => manager.renderEditorState());
});
window.addEventListener('beforeunload', event => {
    if (window.JumpHostManager.isDirty() || window.JumpHostManager.pending) {
        event.preventDefault();
        event.returnValue = '';
    }
});
