(function () {
    'use strict';

    const APP_ROOT = (document.querySelector('meta[name="app-root"]')?.content || '').replace(/\/$/, '');
    const CSRF = document.querySelector('meta[name="csrf-token"]')?.content || '';
    const CURRENT_USER = document.querySelector('meta[name="current-user"]')?.content || '';

    const t = (key, fallback) => (window.i18n && i18n.t ? i18n.t(key) : null) || fallback || key;

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
        parts.push(`<button class="btn btn-danger" data-act="delete" ${isSelf ? 'disabled' : ''}>${escapeHtml(t('admin.delete', 'Delete'))}</button>`);
        return `<div class="admin-actions">${parts.join('')}</div>`;
    }

    function renderUsers(users) {
        const body = document.getElementById('adminUsersBody');
        body.innerHTML = '';
        users.forEach(u => {
            const tr = document.createElement('tr');
            tr.dataset.userId = u.id;
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

    function initUsers() {
        document.getElementById('adminRefreshUsers')?.addEventListener('click', loadUsers);
        document.getElementById('adminUsersBody')?.addEventListener('click', (e) => {
            const btn = e.target.closest('button[data-act]');
            if (!btn || btn.disabled) { return; }
            const tr = btn.closest('tr');
            const userId = tr?.dataset.userId;
            const action = btn.dataset.act;
            if (!userId) { return; }
            if (action === 'delete' && !window.confirm(t('admin.confirmDelete', 'Delete this user permanently?'))) { return; }
            doUserAction(userId, action);
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
    }

    document.addEventListener('DOMContentLoaded', () => {
        if (window.i18n && i18n.updatePageText) { i18n.updatePageText(); }
        initTabs();
        initUsers();
        initAudit();
        initSettings();
        loadUsers();
    });
})();
