(function () {
    'use strict';

    const APP_ROOT = (document.querySelector('meta[name="app-root"]')?.content || '').replace(/\/$/, '');
    const CSRF = document.querySelector('meta[name="csrf-token"]')?.content || '';
    const CURRENT_USER = document.querySelector('meta[name="current-user"]')?.content || '';
    const OIDC_ENABLED = document.querySelector('meta[name="oidc-enabled"]')?.content === 'true';
    const LDAP_ENABLED = document.querySelector('meta[name="ldap-enabled"]')?.content === 'true';
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

    function labelResponsiveTableRows(table) {
        if (!table) { return; }
        const labels = Array.from(table.querySelectorAll('thead th'))
            .map(header => header.textContent.trim());
        table.querySelectorAll('tbody tr').forEach(row => {
            Array.from(row.children).forEach((cell, index) => {
                if (cell.colSpan > 1) {
                    delete cell.dataset.label;
                    return;
                }
                cell.dataset.label = labels[index] || '';
            });
        });
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
        try { data = await res.json(); } catch { /* ignore */ }
        if (!res.ok) {
            const msg = (data && data.error) ? data.error : ('Request failed (' + res.status + ')');
            const error = new Error(msg);
            error.status = res.status;
            error.code = data && data.code;
            throw error;
        }
        return data;
    }

    function decodeBase64url(value) {
        const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
        const raw = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '='));
        return Uint8Array.from(raw, character => character.charCodeAt(0));
    }

    function encodeBase64url(value) {
        const raw = String.fromCharCode.apply(null, new Uint8Array(value));
        return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function decodePasskeyOptions(options) {
        options.challenge = decodeBase64url(options.challenge);
        (options.allowCredentials || []).forEach(item => {
            item.id = decodeBase64url(item.id);
        });
        return options;
    }

    function serializePasskey(credential) {
        return {
            id: credential.id,
            rawId: encodeBase64url(credential.rawId),
            type: credential.type,
            authenticatorAttachment: credential.authenticatorAttachment,
            clientExtensionResults: credential.getClientExtensionResults(),
            response: {
                clientDataJSON: encodeBase64url(credential.response.clientDataJSON),
                authenticatorData: encodeBase64url(credential.response.authenticatorData),
                signature: encodeBase64url(credential.response.signature),
                userHandle: credential.response.userHandle
                    ? encodeBase64url(credential.response.userHandle)
                    : null
            }
        };
    }

    let stepUpGeneration = 0;
    let activeStepUpPrompt = null;

    function closeStepUpPrompt(error, value) {
        const pending = activeStepUpPrompt;
        activeStepUpPrompt = null;
        const modal = document.getElementById('stepUpModal');
        modal?.classList.remove('show');
        modal?.setAttribute('aria-hidden', 'true');
        ['stepUpPassword', 'stepUpTotp'].forEach(id => {
            const input = document.getElementById(id);
            if (input) { input.value = ''; }
        });
        if (!pending) { return; }
        if (error) { pending.reject(error); } else { pending.resolve(value); }
    }

    function requestStepUpValue(method) {
        if (activeStepUpPrompt) {
            closeStepUpPrompt(new Error('Additional authentication was replaced'));
        }
        const password = method === 'password';
        document.getElementById('stepUpPasswordGroup')?.classList.toggle('hidden', !password);
        document.getElementById('stepUpTotpGroup')?.classList.toggle('hidden', password);
        const modal = document.getElementById('stepUpModal');
        modal?.classList.add('show');
        modal?.setAttribute('aria-hidden', 'false');
        setTimeout(() => document.getElementById(
            password ? 'stepUpPassword' : 'stepUpTotp'
        )?.focus(), 0);
        return new Promise((resolve, reject) => {
            activeStepUpPrompt = { method, resolve, reject };
        });
    }

    function initStepUpDialog() {
        const cancel = () => {
            stepUpGeneration += 1;
            closeStepUpPrompt(new Error('Additional authentication was cancelled'));
        };
        document.getElementById('stepUpCancel')?.addEventListener('click', cancel);
        document.getElementById('stepUpCancelButton')?.addEventListener('click', cancel);
        document.getElementById('stepUpModal')?.addEventListener('click', event => {
            if (event.target.id === 'stepUpModal') { cancel(); }
        });
        document.getElementById('stepUpSubmit')?.addEventListener('click', () => {
            if (!activeStepUpPrompt) { return; }
            const field = document.getElementById(
                activeStepUpPrompt.method === 'password'
                    ? 'stepUpPassword'
                    : 'stepUpTotp'
            );
            const value = field?.value || '';
            if (!value) {
                field?.focus();
                return;
            }
            closeStepUpPrompt(null, value);
        });
    }

    function cancelPendingStepUp() {
        stepUpGeneration += 1;
        closeStepUpPrompt(new Error('Additional authentication was cancelled'));
    }

    async function oidcStepUp(action, target, generation) {
        const started = await api('/api/step-up/oidc/start', {
            method: 'POST',
            body: { action, target, continuation: '/admin' }
        });
        const popup = window.open(started.authorization_url, 'webssh-oidc-step-up', 'popup,width=720,height=760');
        if (!popup) { throw new Error('Allow the OIDC authentication popup and try again'); }
        const deadline = Date.now() + 300000;
        while (Date.now() < deadline && generation === stepUpGeneration) {
            await new Promise(resolve => setTimeout(resolve, 500));
            const response = await fetch(APP_ROOT + '/api/step-up/oidc/result', {
                headers: { 'Accept': 'application/json', 'X-CSRFToken': CSRF }
            });
            if (response.ok) {
                const result = await response.json();
                popup.close();
                return result.grant;
            }
            if (response.status !== 404) {
                popup.close();
                const payload = await response.json().catch(() => ({}));
                throw new Error(payload.error || 'OIDC authentication failed');
            }
            if (popup.closed) { break; }
        }
        popup.close();
        throw new Error('Additional authentication was cancelled or expired');
    }

    async function acquireStepUp(action, target) {
        const generation = stepUpGeneration;
        const intent = await api('/api/step-up/intents', {
            method: 'POST', body: { action, target }
        });
        if (intent.grant) { return intent.grant; }
        const methods = intent.methods || [intent.method];
        if (methods.includes('passkey') && window.PublicKeyCredential) {
            const options = decodePasskeyOptions(await api('/api/step-up/passkey/options', {
                method: 'POST', body: { action, target }
            }));
            const credential = await navigator.credentials.get({ publicKey: options });
            const result = await api('/api/step-up/passkey/verify', {
                method: 'POST', body: { credential: serializePasskey(credential) }
            });
            if (generation !== stepUpGeneration) {
                throw new Error('Additional authentication was cancelled');
            }
            return result.grant;
        }
        if (methods.includes('totp')) {
            const code = await requestStepUpValue('totp');
            const result = await api('/api/step-up/totp', {
                method: 'POST', body: { action, target, code }
            });
            return result.grant;
        }
        if (methods.includes('oidc')) {
            return oidcStepUp(action, target, generation);
        }
        const password = await requestStepUpValue('password');
        const result = await api('/api/step-up/password', {
            method: 'POST', body: { action, target, password }
        });
        return result.grant;
    }

    async function stepUpApi(action, target, path, options) {
        const grant = await acquireStepUp(action, target);
        const opts = Object.assign({}, options || {});
        opts.headers = Object.assign({}, opts.headers || {}, {
            'X-WebSSH-Step-Up': grant
        });
        return api(path, opts);
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
                ['users', 'audit', 'settings', 'backup'].forEach(n => {
                    document.getElementById('tab-' + n)?.classList.toggle('hidden', n !== name);
                });
                if (name === 'audit') { loadAudit(); }
                if (name === 'settings') { loadSettings(); }
                if (name === 'backup') { loadRestoreStatus(); }
            });
        });
    }

    // ---- Users ----
    function userActionsHtml(u) {
        const isSelf = u.username === CURRENT_USER;
        const parts = [];
        if (u.is_admin) {
            parts.push(`<button class="btn btn-secondary" data-act="demote" ${isSelf ? 'disabled' : ''}>${escapeHtml(t('admin.demote', 'Demote'))}</button>`);
        } else if (!u.ldap_managed) {
            parts.push(`<button class="btn btn-secondary" data-act="promote">${escapeHtml(t('admin.promote', 'Promote'))}</button>`);
        }
        if (u.is_locked) {
            parts.push(`<button class="btn btn-secondary" data-act="unlock">${escapeHtml(t('admin.unlock', 'Unlock'))}</button>`);
        } else {
            parts.push(`<button class="btn btn-secondary" data-act="lock" ${isSelf ? 'disabled' : ''}>${escapeHtml(t('admin.lock', 'Lock'))}</button>`);
        }
        if (RECOVERY_ENABLED && !u.ldap_managed) {
            parts.push(`<button class="btn btn-secondary" data-act="recovery">${escapeHtml(t('admin.recovery', 'Recovery'))}</button>`);
        }
        if (OIDC_ENABLED && !u.ldap_managed) {
            parts.push(`<button class="btn btn-secondary" data-act="oidc-link">${escapeHtml(t('admin.oidcLink', 'Link OIDC'))}</button>`);
        }
        if (LDAP_ENABLED && !u.is_admin) {
            const label = u.ldap_managed ? 'Manage LDAP' : 'Link LDAP';
            parts.push(`<button class="btn btn-secondary" data-act="ldap-link">${escapeHtml(label)}</button>`);
        }
        if (u.mfa_enabled) {
            parts.push(`<button class="btn btn-secondary" data-act="mfa-reset">${escapeHtml(t('admin.mfaReset', 'Reset MFA'))}</button>`);
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
                `<td>${escapeHtml(u.username)}${u.ldap_managed ? ' <span class="admin-muted">(LDAP)</span>' : ''}${u.username === CURRENT_USER ? ' <span class="admin-muted">(' + escapeHtml(t('admin.you', 'you')) + ')</span>' : ''}</td>` +
                `<td>${role}</td>` +
                `<td>${status}</td>` +
                `<td>${escapeHtml(fmtDate(u.created_at))}</td>` +
                `<td>${escapeHtml(fmtDate(u.last_login))}</td>` +
                `<td>${userActionsHtml(u)}</td>`;
            body.appendChild(tr);
        });
        labelResponsiveTableRows(document.getElementById('adminUsersTable'));
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
            if (action === 'mfa-reset') {
                const row = document.querySelector(`tr[data-user-id="${CSS.escape(String(userId))}"]`);
                const username = row?.dataset.username || '';
                const confirmation = window.prompt(`Type ${username} to reset every MFA factor`);
                if (confirmation === null) { return; }
                await stepUpApi('user.mfa_reset', userId, `/admin/api/users/${userId}/mfa`, {
                    method: 'DELETE', body: { confirm_username: confirmation }
                });
            } else {
                await stepUpApi('user.manage', `${userId}:${action}`, `/admin/api/users/${userId}/${action}`, { method: 'POST' });
            }
            await loadUsers();
            notify(t('admin.actionDone', 'Done'), 'success');
        } catch (e) {
            notify(e.message, 'error');
        }
    }

    const securityRequests = window.WebSSHSecurityUI.createRequestCoordinator({
        persistentChannels: ['action']
    });
    let currentLdapIdentityId = null;

    function clearSecurityReauthentication() {
        ['securityActionConfirmation'].forEach(id => {
            const field = document.getElementById(id);
            if (field) { field.value = ''; }
        });
    }

    function clearSecurityActionFields() {
        ['securityActionConfirmation', 'securityActionSubject', 'securityActionDirectoryUsername', 'securityActionNewPassword', 'securityActionResult']
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
        cancelPendingStepUp();
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
        currentLdapIdentityId = null;
    }

    async function checkLdapStatus() {
        const button = document.getElementById('ldapStatusCheck');
        const result = document.getElementById('ldapStatusResult');
        if (!button || !result) { return; }
        button.disabled = true;
        result.textContent = t('admin.ldapChecking', 'Checking...');
        try {
            const data = await api('/admin/api/ldap/status');
            result.textContent = t(
                'admin.ldapReady',
                'Ready ({transport}, provider {provider})'
            ).replace('{transport}', data.transport)
                .replace('{provider}', data.provider);
        } catch (e) {
            result.textContent = t('admin.unavailable', 'Unavailable');
            notify(e.message, 'error');
        } finally {
            button.disabled = false;
        }
    }

    async function loadLdapIdentity() {
        const context = securityRequests.current();
        if (context?.mode !== 'ldap-link' || !context.userId) { return; }
        const requestState = securityRequests.begin('list', { replace: true });
        if (!requestState) { return; }
        try {
            const data = await api(`/admin/api/users/${requestState.context.userId}/ldap-identity`);
            if (!securityRequests.isCurrent(requestState)) { return; }
            const identity = data.identity;
            currentLdapIdentityId = identity?.id || null;
            const usernameField = document.getElementById('securityActionDirectoryUsername');
            if (usernameField) {
                usernameField.value = identity?.directory_username || requestState.context.username;
                usernameField.disabled = Boolean(identity);
            }
            document.getElementById('securityActionNewPasswordGroup')?.classList.toggle('hidden', !identity);
            document.getElementById('submitSecurityAction').textContent = identity
                ? t('admin.ldapUnlink', 'Unlink LDAP')
                : t('admin.ldapLink', 'Link LDAP');
        } catch (e) {
            if (securityRequests.isCurrent(requestState)) { notify(e.message, 'error'); }
        } finally {
            securityRequests.finish(requestState);
        }
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
        const isLdap = mode === 'ldap-link';
        document.getElementById('securityActionTitle').textContent = isLdap
            ? t('admin.ldapManage', 'Manage LDAP identity')
            : isOidc
            ? t('admin.oidcManage', 'Manage OIDC identities')
            : t('admin.generateRecoveryCodes', 'Generate recovery codes');
        document.getElementById('securityActionHint').textContent = isLdap
            ? t(
                'admin.ldapManageHint',
                'Link {username} to exactly one verified directory identity. LDAP accounts cannot use local fallback authentication.'
            ).replace('{username}', username)
            : isOidc
            ? t(
                'admin.oidcManageHint',
                'Manage stable provider subjects for {username}. Confirm the target username before linking or unlinking.'
            ).replace('{username}', username)
            : t(
                'admin.recoveryGenerateHint',
                'Generate a new one-time recovery set for {username}. Existing recovery codes will stop working.'
            ).replace('{username}', username);
        document.getElementById('securityActionSubjectGroup')?.classList.toggle('hidden', !isOidc);
        document.getElementById('securityActionDirectoryUsernameGroup')?.classList.toggle('hidden', !isLdap);
        document.getElementById('securityActionNewPasswordGroup')?.classList.add('hidden');
        document.getElementById('securityActionOidcListGroup')?.classList.toggle('hidden', !isOidc);
        document.getElementById('securityActionResultGroup')?.classList.add('hidden');
        document.getElementById('submitSecurityAction').textContent = isLdap
            ? t('admin.ldapLink', 'Link LDAP')
            : isOidc
            ? t('admin.oidcLinkIdentity', 'Link OIDC identity')
            : t('admin.continue', 'Continue');
        const modal = document.getElementById('securityActionModal');
        modal?.classList.add('show');
        modal?.setAttribute('aria-hidden', 'false');
        if (isOidc) { loadOidcIdentities(); }
        if (isLdap) { loadLdapIdentity(); }
        document.getElementById('securityActionConfirmation')?.focus();
    }

    async function unlinkOidcIdentity(identityId) {
        const context = securityRequests.current();
        if (context?.mode !== 'oidc-link' || !context.userId) { return; }
        if (!window.confirm(t('admin.oidcUnlinkConfirm', 'Unlink this OIDC identity?'))) { return; }
        const requestState = securityRequests.begin('action');
        if (!requestState) { return; }
        const body = {
            confirm_username: document.getElementById('securityActionConfirmation').value.trim()
        };
        setSecurityActionPending(true);
        try {
            await stepUpApi(
                'oidc.unlink',
                `${requestState.context.userId}:${identityId}`,
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
            confirm_username: document.getElementById('securityActionConfirmation').value.trim()
        };
        let path = `/admin/api/users/${requestState.context.userId}/recovery`;
        let stepUpAction = 'recovery.reset';
        let stepUpTarget = requestState.context.userId;
        if (requestState.context.mode === 'oidc-link') {
            body.subject = document.getElementById('securityActionSubject').value.trim();
            path = `/admin/api/users/${requestState.context.userId}/oidc-link`;
            stepUpAction = 'oidc.link';
        } else if (requestState.context.mode === 'ldap-link') {
            body.directory_username = document.getElementById('securityActionDirectoryUsername').value.trim();
            if (currentLdapIdentityId) {
                body.new_password = document.getElementById('securityActionNewPassword').value;
                path = `/admin/api/users/${requestState.context.userId}/ldap-identities/${currentLdapIdentityId}`;
                stepUpAction = 'ldap.unlink';
                stepUpTarget = `${requestState.context.userId}:${currentLdapIdentityId}`;
            } else {
                path = `/admin/api/users/${requestState.context.userId}/ldap-link`;
                stepUpAction = 'ldap.link';
            }
        }
        setSecurityActionPending(true);
        try {
            const method = requestState.context.mode === 'ldap-link' && currentLdapIdentityId ? 'DELETE' : 'POST';
            const result = await stepUpApi(stepUpAction, stepUpTarget, path, { method, body });
            if (!securityRequests.isCurrent(requestState)) { return; }
            clearSecurityReauthentication();
            if (requestState.context.mode === 'recovery') {
                document.getElementById('securityActionResult').value = (result.codes || []).join('\n');
                document.getElementById('securityActionResultGroup')?.classList.remove('hidden');
                notify(t('admin.recoveryGenerated', 'Recovery codes generated'), 'success');
            } else if (requestState.context.mode === 'oidc-link') {
                notify(t('admin.oidcLinked', 'OIDC identity linked'), 'success');
                document.getElementById('securityActionSubject').value = '';
                await loadOidcIdentities();
            } else {
                notify(
                    currentLdapIdentityId
                        ? t('admin.ldapUnlinked', 'LDAP identity unlinked')
                        : t('admin.ldapLinked', 'LDAP identity linked'),
                    'success'
                );
                currentLdapIdentityId = null;
                closeSecurityAction();
                await loadUsers();
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
            if (action === 'recovery' || action === 'oidc-link' || action === 'ldap-link') {
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
                await stepUpApi('user.create', username, '/admin/api/users', {
                    method: 'POST', body: { username, password, is_admin: isAdmin }
                });
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
        labelResponsiveTableRows(document.getElementById('adminAuditTable'));
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
    const SECURITY_FEATURE_LABELS = Object.freeze({
        passkey: ['admin.featurePasskeys', 'Passkeys'],
        totp: ['admin.featureTotp', 'Authenticator apps (TOTP)'],
        oidc: ['admin.featureOidc', 'OpenID Connect (OIDC)'],
        ldap: ['admin.featureLdap', 'LDAP directory login'],
        recovery: ['admin.featureRecovery', 'Recovery codes']
    });
    let securityFeatureSnapshot = [];

    function securityFeatureLabel(name) {
        const definition = SECURITY_FEATURE_LABELS[name];
        return definition ? t(...definition) : name;
    }

    function renderSecurityFeatures(features) {
        const list = document.getElementById('securityFeatureList');
        const status = document.getElementById('securityFeatureStatus');
        if (!list || !status) { return; }
        securityFeatureSnapshot = Array.isArray(features) ? features : [];
        list.textContent = '';
        for (const feature of securityFeatureSnapshot) {
            const state = window.WebSSHSecurityUI.featureToggleState(feature);
            const row = document.createElement('div');
            row.style.marginTop = '12px';

            const label = document.createElement('label');
            label.className = 'admin-checkbox';
            const input = document.createElement('input');
            input.type = 'checkbox';
            input.dataset.securityFeature = state.name;
            input.checked = state.checked;
            input.disabled = state.disabled;
            const title = document.createElement('strong');
            const labelText = securityFeatureLabel(state.name);
            title.textContent = labelText;
            label.append(input, title);

            const reason = document.createElement('p');
            reason.className = 'admin-muted';
            reason.textContent = window.WebSSHSecurityUI.featureStatusReason(
                feature,
                labelText,
                t
            );
            row.append(label, reason);
            if (['oidc', 'ldap'].includes(state.name)) {
                const configuration = document.createElement('p');
                configuration.className = 'admin-muted';
                configuration.append(t(
                    'admin.deploymentConfiguration',
                    'Deployment configuration'
                ), ': ');
                const keys = document.createElement('code');
                keys.textContent = (feature.configuration_keys || []).join(', ');
                configuration.append(keys, ' · ');
                const guide = document.createElement('a');
                guide.href = feature.documentation_url;
                guide.target = '_blank';
                guide.rel = 'noopener noreferrer';
                guide.textContent = t('admin.openSetupGuide', 'Open setup guide');
                configuration.appendChild(guide);
                row.appendChild(configuration);
            }
            list.appendChild(row);
        }
        status.textContent = securityFeatureSnapshot.length
            ? t('admin.featureStatusLoaded', 'Feature status loaded')
            : t('admin.noAuthenticationFeatures', 'No authentication features reported');
    }

    async function loadSecurityFeatures() {
        const status = document.getElementById('securityFeatureStatus');
        if (!status) { return; }
        status.textContent = t('admin.featureStatusLoading', 'Loading feature status…');
        try {
            const data = await api('/admin/api/security-features');
            renderSecurityFeatures(data.features || []);
        } catch (e) {
            status.textContent = e.message;
            notify(e.message, 'error');
        }
    }

    async function loadSettings() {
        try {
            const data = await api('/admin/api/settings');
            document.getElementById('settingRegistration').checked = !!data.registration_enabled;
        } catch (e) {
            notify(e.message, 'error');
        }
        await loadSecurityFeatures();
    }

    function initSettings() {
        document.getElementById('ldapStatusCheck')?.addEventListener('click', checkLdapStatus);
        document.getElementById('securityFeatureList')?.addEventListener('change', async (event) => {
            const target = event.target;
            if (!target.matches('input[data-security-feature]')) { return; }
            const featureName = target.dataset.securityFeature;
            const enabling = target.checked;
            if (!enabling && !window.confirm(
                window.WebSSHSecurityUI.featureDisableWarning(
                    { name: featureName },
                    securityFeatureLabel(featureName),
                    t
                )
            )) {
                target.checked = true;
                return;
            }
            target.disabled = true;
            try {
                await stepUpApi('security_feature.update', featureName, `/admin/api/security-features/${encodeURIComponent(featureName)}`, {
                    method: 'POST',
                    body: {
                        enabled: enabling,
                        confirm_session_fallback: !enabling
                    }
                });
                notify(t('admin.settingsSaved', 'Settings saved'), 'success');
            } catch (err) {
                notify(err.message, 'error');
            } finally {
                await loadSecurityFeatures();
            }
        });
        document.getElementById('settingRegistration')?.addEventListener('change', async (e) => {
            const target = e.target;
            try {
                const data = await stepUpApi('settings.update', 'global', '/admin/api/settings', {
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
                const data = await stepUpApi('audit.retention', 'global', '/admin/api/audit/retention', {
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

    // ---- Backup and restore ----
    const backupState = {
        createdOperationId: null,
        uploadedOperationId: null,
        confirmationToken: null,
        createPollGeneration: 0,
        uploadPollGeneration: 0
    };
    const restoreStatusFlow = window.WebSSHRestoreStatus.createRestoreStatusFlow({
        storage: window.sessionStorage,
        fetchStatus: () => api('/admin/api/backups/restore/status'),
        checkReady: async () => {
            const response = await fetch(`${APP_ROOT}/ready`, {
                cache: 'no-store',
                credentials: 'same-origin'
            });
            return response.ok;
        },
        present: status => {
            const failed = ['failed', 'rollback_failed'].includes(status.state);
            const message = status.message || status.state;
            setBackupStatus('restoreGlobalStatus', message, failed);
            if (status.state === 'succeeded') {
                notify(message, 'success');
            } else if (failed) {
                notify(message, 'error');
            }
        },
        presentRestarting: () => setBackupStatus(
            'restoreGlobalStatus',
            t('backup.restarting', 'WebSSH is restarting. Sign in again when the service is ready.')
        ),
        reload: () => window.location.reload()
    });

    function setBackupStatus(id, message, error) {
        const target = document.getElementById(id);
        if (!target) { return; }
        target.textContent = message;
        target.classList.toggle('error', !!error);
    }

    function formatBytes(value) {
        const size = Number(value) || 0;
        if (size < 1024) { return `${size} B`; }
        if (size < 1024 * 1024) { return `${(size / 1024).toFixed(1)} KiB`; }
        if (size < 1024 * 1024 * 1024) {
            return `${(size / (1024 * 1024)).toFixed(1)} MiB`;
        }
        return `${(size / (1024 * 1024 * 1024)).toFixed(1)} GiB`;
    }

    async function pollBackupOperation(operationId, generation, generationKey, onComplete) {
        if (!operationId || generation !== backupState[generationKey]) { return; }
        try {
            const record = await api(`/admin/api/backups/${operationId}`);
            if (generation !== backupState[generationKey]) { return; }
            if (['ready', 'verified', 'failed'].includes(record.status)) {
                onComplete(record);
                return;
            }
            onComplete(record, true);
            setTimeout(() => pollBackupOperation(
                operationId, generation, generationKey, onComplete
            ), 900);
        } catch (error) {
            onComplete({ status: 'failed', error: error.message });
        }
    }

    async function createBackup() {
        const button = document.getElementById('backupCreateBtn');
        const download = document.getElementById('backupDownloadBtn');
        button.disabled = true;
        download.disabled = true;
        backupState.createdOperationId = null;
        setBackupStatus('backupCreateStatus', t('backup.creating', 'Creating and verifying backup...'));
        try {
            const record = await stepUpApi('backup.create', 'new', '/admin/api/backups', { method: 'POST' });
            backupState.createdOperationId = record.operation_id;
            const generation = ++backupState.createPollGeneration;
            pollBackupOperation(record.operation_id, generation, 'createPollGeneration', (update, pending) => {
                if (pending) {
                    setBackupStatus('backupCreateStatus', t('backup.creating', 'Creating and verifying backup...'));
                    return;
                }
                button.disabled = false;
                if (update.status === 'ready') {
                    download.disabled = false;
                    setBackupStatus(
                        'backupCreateStatus',
                        t('backup.ready', 'Backup verified and ready for one-time download.')
                    );
                    notify(t('backup.ready', 'Backup verified and ready for one-time download.'), 'success');
                } else {
                    setBackupStatus('backupCreateStatus', update.error || t('backup.failed', 'Backup operation failed.'), true);
                }
            });
        } catch (error) {
            button.disabled = false;
            setBackupStatus('backupCreateStatus', error.message, true);
            notify(error.message, 'error');
        }
    }

    async function downloadBackup() {
        const operationId = backupState.createdOperationId;
        const button = document.getElementById('backupDownloadBtn');
        if (!operationId) { return; }
        button.disabled = true;
        try {
            const grant = await acquireStepUp('backup.download', operationId);
            const response = await fetch(`${APP_ROOT}/admin/api/backups/${operationId}/download`, {
                method: 'POST',
                headers: {
                    'Accept': 'application/zip',
                    'X-CSRFToken': CSRF,
                    'X-WebSSH-Step-Up': grant
                }
            });
            if (!response.ok) {
                const payload = await response.json().catch(() => ({}));
                throw new Error(payload.error || `Download failed (${response.status})`);
            }
            const url = URL.createObjectURL(await response.blob());
            const link = document.createElement('a');
            link.href = url;
            link.download = 'webssh-backup.zip';
            link.click();
            setTimeout(() => URL.revokeObjectURL(url), 1000);
            backupState.createdOperationId = null;
            setBackupStatus('backupCreateStatus', t('backup.downloaded', 'Download started; the server copy is one-time use.'));
        } catch (error) {
            button.disabled = false;
            notify(error.message, 'error');
        }
    }

    function renderBackupSummary(summary) {
        const panel = document.getElementById('backupValidationPanel');
        panel.hidden = false;
        document.getElementById('backupFormatVersion').textContent = summary.format_version;
        document.getElementById('backupDataSchemaVersion').textContent = summary.data_schema_version;
        document.getElementById('backupCurrentDataSchemaVersion').textContent = summary.current_data_schema_version;
        document.getElementById('backupCreatedAt').textContent = summary.created_at
            ? fmtDate(summary.created_at)
            : t('backup.notRecorded', 'Not recorded');
        document.getElementById('backupLegacy').textContent = summary.legacy
            ? t('common.yes', 'Yes')
            : t('common.no', 'No');
        document.getElementById('backupFileCount').textContent = summary.file_count;
        document.getElementById('backupTotalSize').textContent = formatBytes(summary.total_uncompressed_size);
        document.getElementById('backupCompatible').textContent = summary.compatible
            ? t('common.yes', 'Yes')
            : t('common.no', 'No');
        const reasonKeys = {
            'backup data schema is current': 'backup.compatibilityCurrent',
            'legacy archive can be migrated': 'backup.compatibilityLegacy',
            'backup data schema can be migrated': 'backup.compatibilityMigratable',
            'backup data schema is newer than this WebSSH version': 'backup.compatibilityFuture',
            'no complete migration path for backup data schema': 'backup.compatibilityNoMigration'
        };
        const reasonKey = reasonKeys[summary.compatibility_reason];
        document.getElementById('backupCompatibilityReason').textContent = reasonKey
            ? t(reasonKey, summary.compatibility_reason)
            : summary.compatibility_reason;
        document.getElementById('backupRestoreBtn').disabled = summary.compatible !== true;
    }

    async function uploadBackup() {
        const input = document.getElementById('backupUploadFile');
        const button = document.getElementById('backupUploadBtn');
        const file = input.files?.[0];
        if (!file) {
            notify(t('backup.selectFile', 'Select a ZIP backup first.'), 'error');
            return;
        }
        button.disabled = true;
        document.getElementById('backupValidationPanel').hidden = true;
        document.getElementById('backupRestoreBtn').disabled = true;
        setBackupStatus('backupUploadStatus', t('backup.verifying', 'Uploading and verifying backup...'));
        try {
            const grant = await acquireStepUp('backup.upload', 'upload');
            const response = await fetch(`${APP_ROOT}/admin/api/backups/upload`, {
                method: 'POST',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/zip',
                    'X-CSRFToken': CSRF,
                    'X-WebSSH-Step-Up': grant
                },
                body: file
            });
            const record = await response.json().catch(() => ({}));
            if (!response.ok) {
                throw new Error(record.error || `Upload failed (${response.status})`);
            }
            backupState.uploadedOperationId = record.operation_id;
            const generation = ++backupState.uploadPollGeneration;
            pollBackupOperation(record.operation_id, generation, 'uploadPollGeneration', (update, pending) => {
                if (pending) {
                    setBackupStatus('backupUploadStatus', t('backup.verifying', 'Uploading and verifying backup...'));
                    return;
                }
                button.disabled = false;
                input.value = '';
                if (update.status === 'verified') {
                    renderBackupSummary(update.summary);
                    setBackupStatus('backupUploadStatus', t('backup.verified', 'Backup verified successfully.'));
                    notify(t('backup.verified', 'Backup verified successfully.'), 'success');
                } else {
                    backupState.uploadedOperationId = null;
                    setBackupStatus('backupUploadStatus', update.error || t('backup.failed', 'Backup operation failed.'), true);
                }
            });
        } catch (error) {
            button.disabled = false;
            setBackupStatus('backupUploadStatus', error.message, true);
            notify(error.message, 'error');
        }
    }

    function showModal(id, show) {
        const modal = document.getElementById(id);
        modal?.classList.toggle('show', show);
        modal?.setAttribute('aria-hidden', show ? 'false' : 'true');
    }

    function closeRestoreModals() {
        showModal('restoreFirstConfirmModal', false);
        showModal('restoreSecondConfirmModal', false);
        document.getElementById('restoreFirstAcknowledge').checked = false;
        document.getElementById('restoreFinalAcknowledge').checked = false;
        document.getElementById('restorePhrase').value = '';
        cancelPendingStepUp();
        backupState.confirmationToken = null;
    }

    async function continueRestoreConfirmation() {
        if (!document.getElementById('restoreFirstAcknowledge').checked) {
            notify(t('backup.ackRequired', 'Acknowledge the restore impact first.'), 'error');
            return;
        }
        try {
            const result = await stepUpApi(
                'backup.restore_prepare',
                backupState.uploadedOperationId,
                `/admin/api/backups/${backupState.uploadedOperationId}/restore/prepare`,
                {
                    method: 'POST',
                    body: { acknowledge_sensitive_restore: true }
                }
            );
            backupState.confirmationToken = result.confirmation_token;
            showModal('restoreFirstConfirmModal', false);
            showModal('restoreSecondConfirmModal', true);
            document.getElementById('restorePhrase').focus();
        } catch (error) {
            notify(error.message, 'error');
        }
    }

    async function startRestore() {
        const body = {
            confirmation_token: backupState.confirmationToken,
            confirmation_phrase: document.getElementById('restorePhrase').value,
            confirm_destructive_restore: document.getElementById('restoreFinalAcknowledge').checked
        };
        try {
            await stepUpApi(
                'backup.restore',
                backupState.uploadedOperationId,
                `/admin/api/backups/${backupState.uploadedOperationId}/restore`,
                { method: 'POST', body }
            );
            restoreStatusFlow.markPending();
            closeRestoreModals();
            document.getElementById('backupRestoreBtn').disabled = true;
            setBackupStatus(
                'restoreGlobalStatus',
                t('backup.restoreStarted', 'Restore started. WebSSH is entering maintenance mode and will restart.')
            );
            restoreStatusFlow.poll();
        } catch (error) {
            notify(error.message, 'error');
        }
    }

    async function loadRestoreStatus() {
        try {
            const status = await api('/admin/api/backups/restore/status');
            if (status.state !== 'idle') {
                setBackupStatus('restoreGlobalStatus', status.message || status.state,
                    ['failed', 'rollback_failed'].includes(status.state));
            }
        } catch (error) {
            if (!/401|log in/i.test(error.message)) {
                setBackupStatus('restoreGlobalStatus', error.message, true);
            }
        }
    }

    function initBackupRestore() {
        document.getElementById('backupCreateBtn')?.addEventListener('click', createBackup);
        document.getElementById('backupDownloadBtn')?.addEventListener('click', downloadBackup);
        document.getElementById('backupUploadBtn')?.addEventListener('click', uploadBackup);
        document.getElementById('backupRestoreBtn')?.addEventListener('click', () => {
            if (backupState.uploadedOperationId) {
                showModal('restoreFirstConfirmModal', true);
                document.getElementById('restoreFirstAcknowledge').focus();
            }
        });
        document.getElementById('restoreFirstContinue')?.addEventListener('click', continueRestoreConfirmation);
        document.getElementById('restoreStartBtn')?.addEventListener('click', startRestore);
        ['restoreFirstCancel', 'restoreFirstCancelButton', 'restoreSecondCancel', 'restoreSecondCancelButton']
            .forEach(id => document.getElementById(id)?.addEventListener('click', closeRestoreModals));
        if (restoreStatusFlow.isPending()) {
            restoreStatusFlow.resume();
        } else {
            loadRestoreStatus();
        }
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
                    await stepUpApi('host_key.global_delete', entry.id, `/admin/api/host-keys/${entry.id}`, { method: 'DELETE' });
                    await loadGlobalHostKeys();
                });
                row.lastElementChild.appendChild(button);
                body.appendChild(row);
            });
            labelResponsiveTableRows(body.closest('table'));
        } catch (err) {
            notify(err.message, 'error');
        }
    }

    async function addGlobalHostKey() {
        const input = document.getElementById('globalHostKeyEntry');
        const button = document.getElementById('globalHostKeyAdd');
        const entry = input?.value.trim() || '';
        if (!entry) {
            notify(t('admin.globalHostKeyRequired', 'Paste one verified known_hosts entry.'), 'error');
            input?.focus();
            return;
        }
        if (!window.confirm(t(
            'admin.confirmGlobalHostKeyImport',
            'Trust this verified SSH host key for every WebSSH user?'
        ))) { return; }
        if (button) button.disabled = true;
        try {
            await stepUpApi(
                'host_key.global_add',
                'global',
                '/admin/api/host-keys',
                {method: 'POST', body: {entry}},
            );
            input.value = '';
            await loadGlobalHostKeys();
            notify(t('admin.globalHostKeyAdded', 'Global SSH host key imported'), 'success');
        } catch (error) {
            notify(error.message, 'error');
        } finally {
            if (button) button.disabled = false;
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        if (window.i18n && i18n.updatePageText) { i18n.updatePageText(); }
        initStepUpDialog();
        initTabs();
        initUsers();
        initAudit();
        initSettings();
        initBackupRestore();
        document.getElementById('globalHostKeyAdd')?.addEventListener(
            'click', addGlobalHostKey
        );
        loadUsers();
        loadGlobalHostKeys();
        window.addEventListener('languageChanged', () => {
            renderSecurityFeatures(securityFeatureSnapshot);
        });
    });
})();
