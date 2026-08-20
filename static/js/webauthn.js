(function () {
    'use strict';

    const root = (document.querySelector('meta[name="app-root"]')?.content || '').replace(/\/$/, '');
    const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
    const ldapManaged = document.body?.dataset.ldapManaged === 'true';
    const t = (key, fallback) => {
        const translated = window.i18n && i18n.t ? i18n.t(key) : null;
        return translated && translated !== key ? translated : (fallback || key);
    };

    async function api(path, options) {
        const opts = Object.assign({ headers: {} }, options || {});
        opts.headers = Object.assign({
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-CSRFToken': csrf
        }, opts.headers);
        if (opts.body && typeof opts.body === 'object') {
            opts.body = JSON.stringify(opts.body);
        }
        const response = await fetch(root + path, opts);
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            throw new Error(
                data.error || t('common.requestFailed', 'Request failed ({status})')
                    .replace('{status}', response.status)
            );
        }
        return data;
    }

    function bytes(value) {
        const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
        const raw = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '='));
        return Uint8Array.from(raw, character => character.charCodeAt(0));
    }

    function base64url(value) {
        const raw = String.fromCharCode.apply(null, new Uint8Array(value));
        return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function decodeCreationOptions(options) {
        options.challenge = bytes(options.challenge);
        options.user.id = bytes(options.user.id);
        (options.excludeCredentials || []).forEach(item => { item.id = bytes(item.id); });
        return options;
    }

    function decodeRequestOptions(options) {
        options.challenge = bytes(options.challenge);
        (options.allowCredentials || []).forEach(item => { item.id = bytes(item.id); });
        return options;
    }

    function serializeCredential(credential) {
        const response = credential.response;
        const result = {
            id: credential.id,
            rawId: base64url(credential.rawId),
            type: credential.type,
            authenticatorAttachment: credential.authenticatorAttachment,
            clientExtensionResults: credential.getClientExtensionResults(),
            response: { clientDataJSON: base64url(response.clientDataJSON) }
        };
        if (response.attestationObject) {
            result.response.attestationObject = base64url(response.attestationObject);
            result.response.transports = response.getTransports ? response.getTransports() : [];
        } else {
            result.response.authenticatorData = base64url(response.authenticatorData);
            result.response.signature = base64url(response.signature);
            result.response.userHandle = response.userHandle ? base64url(response.userHandle) : null;
        }
        return result;
    }

    function notify(message, type) {
        const container = document.getElementById('notificationContainer');
        if (!container) {
            window.alert(message);
            return;
        }
        const item = document.createElement('div');
        item.className = `notification notification-${type || 'info'}`;
        item.textContent = message;
        container.appendChild(item);
        setTimeout(() => item.remove(), 4000);
    }

    function factorChangeBody() {
        if (ldapManaged) { return {}; }
        const password = window.prompt(t('auth.currentPassword', 'Current password'));
        return password === null ? null : { password };
    }

    async function loadHostKeys() {
        const body = document.getElementById('hostKeyList');
        if (!body) { return; }
        const data = await api('/api/host-keys');
        body.replaceChildren();
        for (const entry of data.entries || []) {
            const row = document.createElement('tr');
            const hostLabel = (entry.hosts || [{ host: entry.host, port: entry.port }])
                .map(item => `${item.host}:${item.port || ''}`).join(', ');
            const presentation = window.WebSSHSecurityUI.describeHostKey(entry, t);
            for (const value of [
                hostLabel,
                presentation.status,
                entry.algorithm,
                entry.fingerprint
            ]) {
                const cell = document.createElement('td');
                cell.textContent = value;
                row.appendChild(cell);
            }
            const action = document.createElement('td');
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
                await api(`/api/host-keys/${entry.id}`, { method: 'DELETE' });
                await loadHostKeys();
            });
            action.appendChild(button);
            row.appendChild(action);
            body.appendChild(row);
        }
    }

    async function loadPasskeys() {
        const container = document.getElementById('passkeyList');
        if (!container || !document.getElementById('passkeyAddBtn')) { return; }
        const data = await api('/api/webauthn/credentials');
        container.replaceChildren();
        for (const credential of data.credentials || []) {
            const row = document.createElement('div');
            row.className = 'admin-toolbar';
            const label = document.createElement('span');
            label.textContent = `${credential.name} · ${new Date(credential.created_at).toLocaleString()}`;
            const button = document.createElement('button');
            button.className = 'btn btn-danger';
            button.textContent = t('common.delete', 'Delete');
            button.addEventListener('click', async () => {
                const body = factorChangeBody();
                if (body === null) { return; }
                await api(`/api/webauthn/credentials/${credential.id}`, {
                    method: 'DELETE',
                    body
                });
                await loadPasskeys();
            });
            row.append(label, button);
            container.appendChild(row);
        }
    }

    async function registerPasskey(legacyUpgrade) {
        try {
            if (!window.PublicKeyCredential) {
                throw new Error(t(
                    'security.passkeysUnsupported',
                    'This browser does not support passkeys'
                ));
            }
            if (legacyUpgrade && !window.confirm(
                t(
                    'security.legacyPasskeyConfirm',
                    'Create a discoverable replacement without excluding older credentials?'
                )
            )) {
                return;
            }
            const body = factorChangeBody();
            if (body === null) { return; }
            const name = window.prompt(
                t('security.passkeyName', 'Passkey name'),
                legacyUpgrade
                    ? t('security.replacementPasskey', 'Replacement passkey')
                    : t('security.passkeyDefaultName', 'Passkey')
            ) || t('security.passkeyDefaultName', 'Passkey');
            if (legacyUpgrade) { body.legacy_upgrade = true; }
            const options = decodeCreationOptions(await api(
                '/api/webauthn/register/options',
                { method: 'POST', body }
            ));
            const credential = await navigator.credentials.create({
                publicKey: options
            });
            await api('/api/webauthn/register/verify', {
                method: 'POST',
                body: { name, credential: serializeCredential(credential) }
            });
            await loadPasskeys();
            notify(t('security.passkeyAdded', 'Passkey added'), 'success');
        } catch (error) {
            notify(error.message, 'error');
        }
    }

    let activeTotpEnrollment = null;

    async function loadTotpAuthenticators() {
        const container = document.getElementById('totpList');
        if (!container) { return; }
        const data = await api('/api/totp/authenticators');
        const state = window.WebSSHSecurityUI.totpAccountState(data);
        container.replaceChildren();
        for (const authenticator of data.authenticators || []) {
            const row = document.createElement('div');
            row.className = 'admin-toolbar';
            const label = document.createElement('span');
            label.textContent = `${authenticator.label} · ${new Date(authenticator.created_at).toLocaleString()}`;
            row.appendChild(label);
            container.appendChild(row);
        }
        if (!state.hasAuthenticator) {
            const empty = document.createElement('p');
            empty.className = 'admin-muted';
            empty.textContent = t(
                'security.noTotpAuthenticators',
                'No authenticator app is enrolled.'
            );
            container.appendChild(empty);
        }
        document.getElementById('totpDisableBtn')?.classList.toggle(
            'hidden',
            !state.canDisable
        );
    }

    async function beginTotpEnrollment() {
        const body = factorChangeBody();
        if (body === null) { return; }
        const label = window.prompt(
            t('security.authenticatorName', 'Authenticator name'),
            t('security.authenticatorDefaultName', 'Authenticator')
        );
        if (label === null) { return; }
        body.label = label;
        const data = await api('/api/totp/enroll', { method: 'POST', body });
        activeTotpEnrollment = data;
        const image = document.getElementById('totpQr');
        image.src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(data.qr_svg);
        document.getElementById('totpSecret').textContent = data.secret;
        document.getElementById('totpEnrollment').classList.remove('hidden');
        document.getElementById('totpActivationCode').focus();
    }

    async function activateTotpEnrollment() {
        if (!activeTotpEnrollment) { return; }
        const code = document.getElementById('totpActivationCode').value
            .replace(/\s+/g, '');
        if (!/^[0-9]{6}$/.test(code)) {
            throw new Error(t(
                'security.invalidTotpCode',
                'Enter a valid six-digit code.'
            ));
        }
        const data = await api('/api/totp/enroll/verify', {
            method: 'POST',
            body: {
                token: activeTotpEnrollment.token,
                code,
                confirm_enable_mfa: true
            }
        });
        activeTotpEnrollment = null;
        document.getElementById('totpEnrollment').classList.add('hidden');
        document.getElementById('totpQr').removeAttribute('src');
        document.getElementById('totpSecret').textContent = '';
        document.getElementById('totpActivationCode').value = '';
        const codes = data.recovery_codes || [];
        if (codes.length) {
            document.getElementById('totpRecoveryCodes').textContent = [
                t(
                    'security.storeRecoveryCodes',
                    'Store these codes now. They will not be shown again.'
                ),
                '',
                ...codes
            ].join('\n');
        }
        await loadTotpAuthenticators();
        notify(t('security.mfaEnabled', 'MFA enabled'), 'success');
    }

    async function disableTotpMfa() {
        if (!window.confirm(t(
            'security.confirmDisableMfa',
            'Disable the MFA requirement for future sign-ins? Enrolled factors remain stored.'
        ))) { return; }
        const body = factorChangeBody();
        if (body === null) { return; }
        body.confirm_disable_mfa = true;
        await api('/api/totp/disable', { method: 'POST', body });
        await loadTotpAuthenticators();
        notify(t('security.mfaDisabled', 'MFA requirement disabled'), 'success');
    }

    document.addEventListener('DOMContentLoaded', () => {
        document.getElementById('hostKeyRefresh')?.addEventListener('click', () => {
            loadHostKeys().catch(error => notify(error.message, 'error'));
        });
        if (document.getElementById('hostKeyList')) {
            loadHostKeys().catch(error => notify(error.message, 'error'));
        }
        document.getElementById('recoveryGenerateBtn')?.addEventListener('click', async () => {
            try {
                const password = window.prompt(t('auth.currentPassword', 'Current password'));
                if (password === null) { return; }
                const data = await api('/api/recovery-codes', {
                    method: 'POST',
                    body: { password }
                });
                document.getElementById('recoveryCodes').textContent = data.codes.join('\n');
                notify(t(
                    'security.storeRecoveryCodes',
                    'Store these codes now. They will not be shown again.'
                ), 'success');
            } catch (error) {
                notify(error.message, 'error');
            }
        });
        document.getElementById('passkeyAddBtn')?.addEventListener('click', () => {
            registerPasskey(false);
        });
        document.getElementById('passkeyUpgradeBtn')?.addEventListener('click', () => {
            registerPasskey(true);
        });
        loadPasskeys().catch(error => notify(error.message, 'error'));
        document.getElementById('totpAddBtn')?.addEventListener('click', () => {
            beginTotpEnrollment().catch(error => notify(error.message, 'error'));
        });
        document.getElementById('totpActivateBtn')?.addEventListener('click', () => {
            activateTotpEnrollment().catch(error => notify(error.message, 'error'));
        });
        document.getElementById('totpDisableBtn')?.addEventListener('click', () => {
            disableTotpMfa().catch(error => notify(error.message, 'error'));
        });
        loadTotpAuthenticators().catch(error => notify(error.message, 'error'));
        document.getElementById('passkeyLoginBtn')?.addEventListener('click', async () => {
            try {
                const options = decodeRequestOptions(await api('/api/webauthn/auth/options', {
                    method: 'POST',
                    body: {}
                }));
                const credential = await navigator.credentials.get({ publicKey: options });
                const result = await api('/api/webauthn/auth/verify', {
                    method: 'POST',
                    body: { credential: serializeCredential(credential) }
                });
                window.location.assign(root + (result.continuation || '/'));
            } catch (error) {
                window.alert(error.message);
            }
        });
        document.getElementById('recoveryLoginBtn')?.addEventListener('click', () => {
            const panel = document.getElementById('recoveryLoginPanel');
            panel?.classList.toggle('hidden');
            if (panel && !panel.classList.contains('hidden')) {
                const username = document.getElementById('username')?.value.trim();
                if (username) {
                    document.getElementById('recoveryUsername').value = username;
                }
                document.getElementById('recoveryUsername')?.focus();
            }
        });
        document.getElementById('submitRecoveryLogin')?.addEventListener('click', async () => {
            try {
                const username = document.getElementById('recoveryUsername').value.trim();
                const code = document.getElementById('recoveryCode').value.trim();
                await api('/login/recovery', {
                    method: 'POST',
                    body: { username, code }
                });
                window.location.assign(root + '/');
            } catch (error) {
                window.alert(error.message);
            }
        });
    });
})();
