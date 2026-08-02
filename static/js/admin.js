(function () {
    'use strict';

    const APP_ROOT = (document.querySelector('meta[name="app-root"]')?.content || '').replace(/\/$/, '');
    const CSRF = document.querySelector('meta[name="csrf-token"]')?.content || '';
    const CURRENT_USER = document.querySelector('meta[name="current-user"]')?.content || '';
    const OIDC_ENABLED = document.querySelector('meta[name="oidc-enabled"]')?.content === 'true';
    const RECOVERY_ENABLED = document.querySelector('meta[name="recovery-enabled"]')?.content === 'true';

    const t = (key, fallback) => {
        const translated = window.i18n && i18n.t ? i18n.t(key) : null;
        return translated && translated !== key ? translated : (fallback || key);
    };

    function escapeHtml(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function notify(message, type) {
        const container = document.getElementById('notificationContainer');
        if (!container) { return; }
        const el = document.createElement('div');
        el.className = 'notification notification-' + (type || 'info');
        el.textContent = message;
        container.appendChild(el);
        setTimeout(() => el.remove(), type === 'error' ? 4000 : 2500);
    }

    async function api(path, options) {
        const opts = Object.assign({ headers: {} }, options || {});
        opts.headers = Object.assign({
            'Accept': 'application/json',
            'X-CSRFToken': CSRF
        }, opts.headers);
        if (opts.body && typeof opts.body === 'object') {
            opts.headers['Content-Type'] = 'application/json';
            opts.body = JSON.stringify(opts.body);
        }
        const res = await fetch(APP_ROOT + path, opts);
        let data = null;
        try { data = await res.json(); } catch (e) { /* ignore */ }
        if (!res.ok) {
            const msg = (data && data.error) ? data.error : ('Request failed (' + res.status + ')');
            throw new Error(msg);
        }
        return data;
    }

    function fmtDate(iso) {
        if (!iso) { return '—'; }
        const d = new Date(iso);
        if (isNaN(d.getTime())) { return iso; }
        return d.toLocaleString();
    }

    // ---- Tabs ----
    function initTabs() {
        document.querySelectorAll('.admin-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.admin-tab').forEach(x => x.classList.remove('active'));
                tab.classList.add('active');
                const name = tab.dataset.tab;
                ['users', 'audit', 'settings'].forEach(n => {
                    document.getElementById('tab-' + n)?.classList.toggle('hidden', n !== name);
                });
                if (name === 'audit') { loadAudit(); }
                if (name === 'settings') { loadSettings(); }
            });
        });
    }

    // ---- Users ----
    function userActionsHtml(u) {
        const isSelf = u.username === CURRENT_USER;
        const parts = [];
        if (u.is_admin) {
            parts.push(`<button class="btn btn-secondary" data-act="demote" ${isSelf ? 'disabled' : ''}>${escapeHtml(t('admin.demote', 'Demote'))}</button>`);
        } else {
            parts.push(`<button class="btn btn-secondary" data-act="promote">${escapeHtml(t('admin.promote', 'Promote'))}</button>`);
        }
        if (u.is_locked) {
            parts.push(`<button class="btn btn-secondary" data-act="unlock">${escapeHtml(t('admin.unlock', 'Unlock'))}</button>`);
        } else {
            parts.push(`<button class="btn btn-secondary" data-act="lock" ${isSelf ? 'disabled' : ''}>${escapeHtml(t('admin.lock', 'Lock'))}</button>`);
        }
        if (RECOVERY_ENABLED) {
            parts.push(`<button class="btn btn-secondary" data-act="recovery">${escapeHtml(t('admin.recovery', 'Recovery'))}</button>`);
        }
        if (OIDC_ENABLED) {
            parts.push(`<button class="btn btn-secondary" data-act="oidc-link">${escapeHtml(t('admin.oidcLink', 'Link OIDC'))}</button>`);
        }
        parts.push(`<button class="btn btn-danger" data-act="delete" ${isSelf ? 'disabled' : ''}>${escapeHtml(t('admin.delete', 'Delete'))}</button>`);
        return `<div class="admin-actions">${parts.join('')}</div>`;
    }

    function renderUsers(users) {
        const body = document.getElementById('adminUsersBody');
        body.innerHTML = '';
        users.forEach(u => {
            const tr = document.createElement('tr');
            tr.dataset.userId = u.id;
            tr.dataset.username = u.username;
            const role = u.is_admin
                ? `<span class="admin-badge admin">${escapeHtml(t('admin.roleAdmin', 'Admin'))}</span>`
                : `<span class="admin-badge">${escapeHtml(t('admin.roleUser', 'User'))}</span>`;
            const status = u.is_locked
                ? `<span class="admin-badge locked">${escapeHtml(t('admin.statusLocked', 'Locked'))}</span>`
                : `<span class="admin-badge">${escapeHtml(t('admin.statusActive', 'Active'))}</span>`;
            tr.innerHTML =
                `<td>${u.id}</td>` +
                `<td>${escapeHtml(u.username)}${u.username === CURRENT_USER ? ' <span class="admin-muted">(' + escapeHtml(t('admin.you', 'you')) + ')</span>' : ''}</td>` +
                `<td>${role}</td>` +
                `<td>${status}</td>` +
                `<td>${escapeHtml(fmtDate(u.created_at))}</td>` +
                `<td>${escapeHtml(fmtDate(u.last_login))}</td>` +
                `<td>${userActionsHtml(u)}</td>`;
            body.appendChild(tr);
        });
    }

    async function loadUsers() {
        try {
            const data = await api('/admin/api/users');
            renderUsers(data.users || []);
        } catch (e) {
            notify(e.message, 'error');
        }
    }

    async function doUserAction(userId, action) {
        try {
            await api(`/admin/api/users/${userId}/${action}`, { method: 'POST' });
            await loadUsers();
            notify(t('admin.actionDone', 'Done'), 'success');
        } catch (e) {
            notify(e.message, 'error');
        }
    }

    const securityRequests = window.WebSSHSecurityUI.createRequestCoordinator({
        persistentChannels: ['action']
    });

    function clearSecurityReauthentication() {
        ['securityActionPassword', 'securityActionConfirmation'].forEach(id => {
            const field = document.getElementById(id);
            if (field) { field.value = ''; }
        });
    }

    function clearSecurityActionFields() {
        ['securityActionPassword', 'securityActionConfirmation', 'securityActionSubject', 'securityActionResult']
            .forEach(id => {
                const field = document.getElementById(id);
                if (field) { field.value = ''; }
            });
    }

    function setSecurityActionPending(pending) {
        const submit = document.getElementById('submitSecurityAction');
        if (submit) { submit.disabled = pending; }
        document.querySelectorAll(
            '#securityActionOidcList button[data-oidc-identity-id]'
        ).forEach(button => { button.disabled = pending; });
    }

    function closeSecurityAction() {
        securityRequests.close();
        const modal = document.getElementById('securityActionModal');
        modal?.classList.remove('show');
        modal?.setAttribute('aria-hidden', 'true');
        setSecurityActionPending(securityRequests.isPending('action'));
        clearSecurityActionFields();
        document.getElementById('securityActionResultGroup')?.classList.add('hidden');
        document.getElementById('securityActionOidcListGroup')?.classList.add('hidden');
        const oidcList = document.getElementById('securityActionOidcList');
        if (oidcList) { oidcList.textContent = ''; }
    }

    async function loadOidcIdentities() {
        const context = securityRequests.current();
        if (context?.mode !== 'oidc-link' || !context.userId) { return; }
        const requestState = securityRequests.begin('list', { replace: true });
        if (!requestState) { return; }
        const list = document.getElementById('securityActionOidcList');
        if (!list) {
            securityRequests.finish(requestState);
            return;
        }
        list.textContent = t('admin.loading', 'Loading...');
        try {
            const data = await api(
                `/admin/api/users/${requestState.context.userId}/oidc-identities`
            );
            if (!securityRequests.isCurrent(requestState)) { return; }
            const identities = data.identities || [];
            if (!identities.length) {
                list.textContent = t('admin.oidcNone', 'No linked OIDC identities');
                return;
            }
            list.innerHTML = identities.map(identity => (
                `<div class="admin-oidc-identity">` +
                    `<div class="admin-oidc-identity-details">` +
                        `<code>${escapeHtml(identity.subject)}</code>` +
                        `<small>${escapeHtml(identity.issuer)}</small>` +
                    `</div>` +
                    `<button type="button" class="btn btn-danger" data-oidc-identity-id="${escapeHtml(identity.id)}">` +
                        `${escapeHtml(t('admin.oidcUnlink', 'Unlink'))}` +
                    `</button>` +
                `</div>`
            )).join('');
            setSecurityActionPending(securityRequests.isPending('action'));
        } catch (e) {
            if (!securityRequests.isCurrent(requestState)) { return; }
            list.textContent = e.message;
            notify(e.message, 'error');
        } finally {
            securityRequests.finish(requestState);
        }
    }

    function openSecurityAction(mode, userId, username) {
        securityRequests.open({
            mode,
            userId: String(userId),
            username: String(username)
        });
        setSecurityActionPending(securityRequests.isPending('action'));
        clearSecurityActionFields();
        const isOidc = mode === 'oidc-link';
        document.getElementById('securityActionTitle').textContent = isOidc
            ? t('admin.oidcManage', 'Manage OIDC identities')
            : t('admin.generateRecoveryCodes', 'Generate recovery codes');
        document.getElementById('securityActionHint').textContent = isOidc
            ? t(
                'admin.oidcManageHint',
                'Manage stable provider subjects for {username}. Enter your password and the target username before linking or unlinking.'
            ).replace('{username}', username)
            : t(
                'admin.recoveryGenerateHint',
                'Generate a new one-time recovery set for {username}. Existing recovery codes will stop working.'
            ).replace('{username}', username);
        document.getElementById('securityActionSubjectGroup')?.classList.toggle('hidden', !isOidc);
        document.getElementById('securityActionOidcListGroup')?.classList.toggle('hidden', !isOidc);
        document.getElementById('securityActionResultGroup')?.classList.add('hidden');
        document.getElementById('submitSecurityAction').textContent = isOidc
            ? t('admin.oidcLinkIdentity', 'Link OIDC identity')
            : t('admin.continue', 'Continue');
        const modal = document.getElementById('securityActionModal');
        modal?.classList.add('show');
        modal?.setAttribute('aria-hidden', 'false');
        if (isOidc) { loadOidcIdentities(); }
        document.getElementById('securityActionPassword')?.focus();
    }

    async function unlinkOidcIdentity(identityId) {
        const context = securityRequests.current();
        if (context?.mode !== 'oidc-link' || !context.userId) { return; }
        if (!window.confirm(t('admin.oidcUnlinkConfirm', 'Unlink this OIDC identity?'))) { return; }
        const requestState = securityRequests.begin('action');
        if (!requestState) { return; }
        const body = {
            password: document.getElementById('securityActionPassword').value,
            confirm_username: document.getElementById('securityActionConfirmation').value.trim()
        };
        setSecurityActionPending(true);
        try {
            await api(
                `/admin/api/users/${requestState.context.userId}/oidc-identities/${identityId}`,
                { method: 'DELETE', body }
            );
            if (!securityRequests.isCurrent(requestState)) { return; }
            clearSecurityReauthentication();
            notify(t('admin.oidcUnlinked', 'OIDC identity unlinked'), 'success');
            await loadOidcIdentities();
        } catch (e) {
            if (securityRequests.isCurrent(requestState)) {
                notify(e.message, 'error');
            }
        } finally {
            securityRequests.finish(requestState);
            if (securityRequests.current()) {
                setSecurityActionPending(securityRequests.isPending('action'));
            }
        }
    }

    async function submitSecurityAction() {
        const context = securityRequests.current();
        if (!context?.mode || !context.userId) { return; }
        const requestState = securityRequests.begin('action');
        if (!requestState) { return; }
        const body = {
            password: document.getElementById('securityActionPassword').value,
            confirm_username: document.getElementById('securityActionConfirmation').value.trim()
        };
        let path = `/admin/api/users/${requestState.context.userId}/recovery`;
        if (requestState.context.mode === 'oidc-link') {
            body.subject = document.getElementById('securityActionSubject').value.trim();
            path = `/admin/api/users/${requestState.context.userId}/oidc-link`;
        }
        setSecurityActionPending(true);
        try {
            const result = await api(path, { method: 'POST', body });
            if (!securityRequests.isCurrent(requestState)) { return; }
            clearSecurityReauthentication();
            if (requestState.context.mode === 'recovery') {
                document.getElementById('securityActionResult').value = (result.codes || []).join('\n');
                document.getElementById('securityActionResultGroup')?.classList.remove('hidden');
                notify(t('admin.recoveryGenerated', 'Recovery codes generated'), 'success');
            } else {
                notify(t('admin.oidcLinked', 'OIDC identity linked'), 'success');
                document.getElementById('securityActionSubject').value = '';
                await loadOidcIdentities();
            }
        } catch (e) {
            if (securityRequests.isCurrent(requestState)) {
                notify(e.message, 'error');
            }
        } finally {
            securityRequests.finish(requestState);
            if (securityRequests.current()) {
                setSecurityActionPending(securityRequests.isPending('action'));
            }
        }
    }

    function initUsers() {
        document.getElementById('adminRefreshUsers')?.addEventListener('click', loadUsers);
        document.getElementById('adminUsersBody')?.addEventListener('click', (e) => {
            const btn = e.target.closest('button[data-act]');
            if (!btn || btn.disabled) { return; }
            const tr = btn.closest('tr');
            const userId = tr?.dataset.userId;
            const username = tr?.dataset.username;
            const action = btn.dataset.act;
            if (!userId) { return; }
            if (action === 'recovery' || action === 'oidc-link') {
                openSecurityAction(action, userId, username);
                return;
            }
            if (action === 'delete' && !window.confirm(t('admin.confirmDelete', 'Delete this user permanently?'))) { return; }
            doUserAction(userId, action);
        });
        document.getElementById('closeSecurityAction')?.addEventListener('click', closeSecurityAction);
        document.getElementById('securityActionModal')?.addEventListener('click', e => {
            if (e.target.id === 'securityActionModal') { closeSecurityAction(); }
        });
        document.getElementById('submitSecurityAction')?.addEventListener('click', submitSecurityAction);
        document.getElementById('securityActionOidcList')?.addEventListener('click', e => {
            const button = e.target.closest('button[data-oidc-identity-id]');
            if (button) { unlinkOidcIdentity(button.dataset.oidcIdentityId); }
        });

        // Add-user modal
        const modal = document.getElementById('addUserModal');
        const open = () => {
            if (!modal) { return; }
            modal.classList.add('show');
            modal.setAttribute('aria-hidden', 'false');
            document.getElementById('newUsername')?.focus();
        };
        const close = () => {
            if (!modal) { return; }
            modal.classList.remove('show');
            modal.setAttribute('aria-hidden', 'true');
            document.getElementById('adminAddUserBtn')?.focus();
        };
        document.getElementById('adminAddUserBtn')?.addEventListener('click', open);
        document.getElementById('closeAddUser')?.addEventListener('click', close);
        modal?.addEventListener('click', (e) => { if (e.target === modal) { close(); } });
        document.getElementById('submitNewUser')?.addEventListener('click', async () => {
            const username = document.getElementById('newUsername').value.trim();
            const password = document.getElementById('newPassword').value;
            const isAdmin = document.getElementById('newIsAdmin').checked;
            try {
                await api('/admin/api/users', { method: 'POST', body: { username, password, is_admin: isAdmin } });
                close();
                document.getElementById('newUsername').value = '';
                document.getElementById('newPassword').value = '';
                document.getElementById('newIsAdmin').checked = false;
                await loadUsers();
                notify(t('admin.userCreated', 'User created'), 'success');
            } catch (e) {
                notify(e.message, 'error');
            }
        });
    }

    // ---- Audit logs ----
    const audit = { offset: 0, limit: 100, total: 0 };

    function renderAudit(items) {
        const body = document.getElementById('adminAuditBody');
        body.innerHTML = '';
        if (!items.length) {
            body.innerHTML = `<tr><td colspan="4" class="admin-muted">${escapeHtml(t('admin.noLogs', 'No log entries'))}</td></tr>`;
            return;
        }
        items.forEach(e => {
            const tr = document.createElement('tr');
            const level = e.level || '';
            tr.innerHTML =
                `<td>${escapeHtml(fmtDate(e.timestamp))}</td>` +
                `<td><span class="admin-badge level-${escapeHtml(level)}">${escapeHtml(level)}</span></td>` +
                `<td>${escapeHtml(e.logger || '')}</td>` +
                `<td class="admin-message">${escapeHtml(e.message || '')}</td>`;
            body.appendChild(tr);
        });
    }

    function updateAuditPageInfo() {
        const info = document.getElementById('auditPageInfo');
        const from = audit.total === 0 ? 0 : audit.offset + 1;
        const to = Math.min(audit.offset + audit.limit, audit.total);
        info.textContent = `${from}–${to} / ${audit.total}`;
        document.getElementById('auditPrev').disabled = audit.offset <= 0;
        document.getElementById('auditNext').disabled = audit.offset + audit.limit >= audit.total;
    }

    async function loadAudit() {
        const level = document.getElementById('auditLevel').value;
        const q = document.getElementById('auditSearch').value.trim();
        const params = new URLSearchParams({ offset: audit.offset, limit: audit.limit });
        if (level) { params.set('level', level); }
        if (q) { params.set('q', q); }
        try {
            const data = await api('/admin/api/audit?' + params.toString());
            audit.total = data.total || 0;
            audit.offset = data.offset || 0;
            renderAudit(data.items || []);
            updateAuditPageInfo();
        } catch (e) {
            notify(e.message, 'error');
        }
    }

    function initAudit() {
        document.getElementById('auditRefresh')?.addEventListener('click', () => { audit.offset = 0; loadAudit(); });
        document.getElementById('auditLevel')?.addEventListener('change', () => { audit.offset = 0; loadAudit(); });
        let searchTimer = null;
        document.getElementById('auditSearch')?.addEventListener('input', () => {
            clearTimeout(searchTimer);
            searchTimer = setTimeout(() => { audit.offset = 0; loadAudit(); }, 300);
        });
        document.getElementById('auditPrev')?.addEventListener('click', () => {
            audit.offset = Math.max(0, audit.offset - audit.limit);
            loadAudit();
        });
        document.getElementById('auditNext')?.addEventListener('click', () => {
            audit.offset = audit.offset + audit.limit;
            loadAudit();
        });
        document.getElementById('auditExportBtn')?.addEventListener('click', async () => {
            const params = new URLSearchParams();
            const level = document.getElementById('auditLevel').value;
            const q = document.getElementById('auditSearch').value.trim();
            if (level) { params.set('level', level); }
            if (q) { params.set('q', q); }
            try {
                const result = await window.WebSSHSecurityUI.downloadAuditExport(
                    APP_ROOT + '/admin/api/audit/export?' + params.toString(),
                    { translate: t }
                );
                if (result.truncated) {
                    notify(
                        t(
                            'admin.auditExportTruncated',
                            'Audit export contains only the newest {count} retained records because the scan limit was reached.'
                        ).replace('{count}', result.scanned),
                        'warning'
                    );
                }
            } catch (err) {
                notify(err.message, 'error');
            }
        });
    }

    // ---- Settings ----
    async function loadSettings() {
        try {
            const data = await api('/admin/api/settings');
            document.getElementById('settingRegistration').checked = !!data.registration_enabled;
        } catch (e) {
            notify(e.message, 'error');
        }
    }

    function initSettings() {
        document.getElementById('settingRegistration')?.addEventListener('change', async (e) => {
            const target = e.target;
            try {
                const data = await api('/admin/api/settings', {
                    method: 'POST',
                    body: { registration_enabled: target.checked }
                });
                target.checked = !!data.registration_enabled;
                notify(t('admin.settingsSaved', 'Settings saved'), 'success');
            } catch (err) {
                target.checked = !target.checked; // revert on failure
                notify(err.message, 'error');
            }
        });
        document.getElementById('auditRetentionSave')?.addEventListener('click', async () => {
            const value = Number(document.getElementById('auditRetention').value);
            try {
                const data = await api('/admin/api/audit/retention', {
                    method: 'POST',
                    body: { backup_count: value }
                });
                document.getElementById('auditRetention').value = data.backup_count;
                notify(t('admin.auditRetentionSaved', 'Audit retention saved'), 'success');
            } catch (err) {
                notify(err.message, 'error');
            }
        });
        document.getElementById('globalHostKeyRefresh')?.addEventListener('click', loadGlobalHostKeys);
    }

    async function loadGlobalHostKeys() {
        const body = document.getElementById('globalHostKeyList');
        if (!body) { return; }
        try {
            const data = await api('/admin/api/host-keys');
            body.innerHTML = '';
            const entries = data.entries || [];
            if (entries.length === 0) {
                const row = document.createElement('tr');
                row.innerHTML = `<td colspan="5" class="admin-muted">${escapeHtml(
                    t('admin.noHostKeys', 'No global host keys stored.')
                )}</td>`;
                body.appendChild(row);
                return;
            }
            entries.forEach(entry => {
                const row = document.createElement('tr');
                const hostLabel = (entry.hosts || [{ host: entry.host, port: entry.port }])
                    .map(item => `${item.host}:${item.port || ''}`).join(', ');
                const presentation = window.WebSSHSecurityUI.describeHostKey(entry, t);
                row.innerHTML =
                    `<td>${escapeHtml(hostLabel)}</td>` +
                    `<td>${escapeHtml(presentation.status)}</td>` +
                    `<td>${escapeHtml(entry.algorithm)}</td>` +
                    `<td>${escapeHtml(entry.fingerprint)}</td>` +
                    '<td></td>';
                const button = document.createElement('button');
                button.className = 'btn btn-danger';
                button.textContent = presentation.action;
                button.addEventListener('click', async () => {
                    if (!window.confirm(
                        window.WebSSHSecurityUI.hostKeyConfirmation(
                            entry,
                            hostLabel,
                            t
                        )
                    )) { return; }
                    await api(`/admin/api/host-keys/${entry.id}`, { method: 'DELETE' });
                    await loadGlobalHostKeys();
                });
                row.lastElementChild.appendChild(button);
                body.appendChild(row);
            });
        } catch (err) {
            notify(err.message, 'error');
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        if (window.i18n && i18n.updatePageText) { i18n.updatePageText(); }
        initTabs();
        initUsers();
        initAudit();
        initSettings();
        loadUsers();
        loadGlobalHostKeys();
    });
})();
