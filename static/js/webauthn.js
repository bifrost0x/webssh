(function () {
    'use strict';

    const root = (document.querySelector('meta[name="app-root"]')?.content || '').replace(/\/$/, '');
    const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
    const recoveryMode = document.body?.dataset.recoveryMode === 'true';
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

    function notify(message, type, action) {
        const presentation = typeof message === 'object' && message !== null
            ? message
            : { message, type, action };
        const container = document.getElementById('authNotificationContainer')
            || document.getElementById('notificationContainer');
        if (!container) {
            console.warn(String(presentation.message || 'Authentication notice'));
            return;
        }
        const item = document.createElement('div');
        item.className = `notification notification-${presentation.type || 'info'}`;
        item.setAttribute('role', presentation.type === 'error' ? 'alert' : 'status');
        const copy = document.createElement('span');
        copy.textContent = String(presentation.message || '');
        item.appendChild(copy);
        if (presentation.action?.url && presentation.action?.label) {
            const link = document.createElement('a');
            link.className = 'auth-notification-action';
            link.href = presentation.action.url;
            link.textContent = presentation.action.label;
            item.appendChild(link);
        }
        container.appendChild(item);
        setTimeout(() => item.remove(), 4000);
    }

    let confirmationRequest = null;

    function closeConfirmation(result) {
        const modal = document.getElementById('securityConfirmationModal');
        if (!modal || !confirmationRequest) { return; }
        const resolve = confirmationRequest.resolve;
        confirmationRequest = null;
        modal.classList.remove('show');
        modal.setAttribute('aria-hidden', 'true');
        document.getElementById('securityConfirmationForm')?.reset();
        document.getElementById('securityConfirmationError')?.classList.add('hidden');
        resolve(result);
    }

    function requestConfirmation(options) {
        const modal = document.getElementById('securityConfirmationModal');
        if (!modal) { return Promise.resolve(null); }
        if (confirmationRequest) { closeConfirmation(null); }
        const settings = Object.assign({
            authentication: null,
            methodChoices: null,
            preferredMethod: null,
            label: false,
            account: false,
            labelText: 'Name',
            labelDefault: '',
            hint: 'Confirm this account security change.'
        }, options || {});
        const passwordAuthentication = ['password', 'ldap'].includes(
            settings.authentication
        );
        document.getElementById('securityConfirmationHint').textContent = settings.hint;
        document.getElementById('securityConfirmationLabelText').textContent = settings.labelText;
        document.getElementById('securityConfirmationPasswordGroup').classList.toggle('hidden', !passwordAuthentication);
        document.getElementById('securityConfirmationTotpGroup').classList.toggle('hidden', settings.authentication !== 'totp');
        const methodGroup = document.getElementById('securityConfirmationMethodGroup');
        const methodSelect = document.getElementById('securityConfirmationMethod');
        const methodChoices = Array.isArray(settings.methodChoices)
            ? settings.methodChoices
            : [];
        methodGroup.classList.toggle('hidden', methodChoices.length === 0);
        methodSelect.replaceChildren();
        const methodLabels = {
            oidc: t('security.methodOidc', 'Identity provider'),
            passkey: t('security.methodPasskey', 'Passkey'),
            totp: t('security.methodTotp', 'Authenticator app'),
            ldap: t('security.methodLdap', 'Directory password'),
            password: t('security.methodPassword', 'WebSSH password')
        };
        for (const method of methodChoices) {
            const option = document.createElement('option');
            option.value = method;
            option.textContent = methodLabels[method] || method;
            option.selected = method === settings.preferredMethod;
            methodSelect.appendChild(option);
        }
        document.getElementById('securityConfirmationPasswordText').textContent = settings.authentication === 'ldap'
            ? t('security.directoryPassword', 'Directory password')
            : t('auth.currentPassword', 'Current password');
        document.getElementById('securityConfirmationLabelGroup').classList.toggle('hidden', !settings.label);
        document.getElementById('securityConfirmationAccountGroup').classList.toggle('hidden', !settings.account);
        document.getElementById('securityConfirmationLabel').value = settings.labelDefault;
        document.getElementById('securityConfirmationError').classList.add('hidden');
        modal.classList.add('show');
        modal.setAttribute('aria-hidden', 'false');
        const firstField = methodChoices.length
            ? methodSelect
            : passwordAuthentication
            ? document.getElementById('securityConfirmationPassword')
            : settings.authentication === 'totp'
                ? document.getElementById('securityConfirmationTotp')
            : settings.label
                ? document.getElementById('securityConfirmationLabel')
                : document.getElementById('securityConfirmationAccount');
        queueMicrotask(() => firstField?.focus());
        return new Promise(resolve => {
            confirmationRequest = { resolve, settings };
        });
    }

    function submitConfirmation() {
        if (!confirmationRequest) { return; }
        const settings = confirmationRequest.settings;
        const result = {};
        if (Array.isArray(settings.methodChoices) && settings.methodChoices.length) {
            result.method = document.getElementById('securityConfirmationMethod').value;
        }
        if (['password', 'ldap'].includes(settings.authentication)) {
            result.secret = document.getElementById('securityConfirmationPassword').value;
            if (!result.secret) {
                const error = document.getElementById('securityConfirmationError');
                error.textContent = t('auth.currentPasswordRequired', 'Current password is required.');
                error.classList.remove('hidden');
                return;
            }
        }
        if (settings.authentication === 'totp') {
            result.secret = document.getElementById('securityConfirmationTotp').value
                .replace(/\s+/g, '');
            if (!/^[0-9]{6}$/.test(result.secret)) {
                const error = document.getElementById('securityConfirmationError');
                error.textContent = t('security.invalidTotpCode', 'Enter a valid six-digit code.');
                error.classList.remove('hidden');
                return;
            }
        }
        if (settings.label) {
            result.label = document.getElementById('securityConfirmationLabel').value.trim();
            if (!result.label) {
                const error = document.getElementById('securityConfirmationError');
                error.textContent = settings.labelText + ' is required.';
                error.classList.remove('hidden');
                return;
            }
        }
        if (settings.account) {
            result.account = document.getElementById('securityConfirmationAccount').value.trim();
            if (!result.account) {
                const error = document.getElementById('securityConfirmationError');
                error.textContent = t('security.confirmAccountName', 'Type your account name to confirm.');
                error.classList.remove('hidden');
                return;
            }
        }
        closeConfirmation(result);
    }

    async function requestStepUpSecret(method) {
        const result = await requestConfirmation({
            authentication: method,
            hint: method === 'ldap'
                ? t('security.confirmWithDirectory', 'Confirm with the password you use for directory sign-in.')
                : method === 'totp'
                    ? t('security.confirmWithTotp', 'Enter a current code from your authenticator app.')
                    : t('security.confirmFactorChange', 'Confirm this account security change.')
        });
        return result === null ? null : result.secret;
    }

    async function chooseStepUpMethod(methods, preferredMethod) {
        const result = await requestConfirmation({
            methodChoices: methods,
            preferredMethod,
            hint: t(
                'security.chooseConfirmationMethod',
                'Choose how you want to confirm this security change.'
            )
        });
        return result === null ? null : result.method;
    }

    const accountStepUp = window.WebSSHSecurityUI.createAccountStepUpClient({
        api,
        chooseMethod: chooseStepUpMethod,
        requestSecret: requestStepUpSecret,
        getPasskeyAssertion: async publicKey => navigator.credentials.get({
            publicKey: decodeRequestOptions(publicKey)
        }),
        serializeCredential,
        openAuthorization: url => window.open(
            url,
            'webssh-account-step-up',
            'popup,width=720,height=760'
        )
    });

    async function stepUpHeaders(action, target) {
        if (recoveryMode) { return {}; }
        const grant = await accountStepUp.authorize(action, target);
        return grant ? accountStepUp.header(grant) : null;
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
                if (!window.confirm(t(
                    'security.confirmDeletePasskey',
                    'Delete this passkey? Make sure another sign-in method remains available.'
                ))) { return; }
                const headers = await stepUpHeaders('passkey.delete', credential.id);
                if (headers === null) { return; }
                await api(`/api/webauthn/credentials/${credential.id}`, {
                    method: 'DELETE',
                    headers
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
            const defaultName = legacyUpgrade
                ? t('security.replacementPasskey', 'Replacement passkey')
                : t('security.passkeyDefaultName', 'Passkey');
            const details = await requestConfirmation({
                label: true,
                labelText: t('security.passkeyName', 'Passkey name'),
                labelDefault: defaultName,
                hint: t('security.confirmFactorChange', 'Confirm the passkey enrollment for this account.')
            });
            if (details === null) { return; }
            const headers = await stepUpHeaders('passkey.enroll');
            if (headers === null) { return; }
            const name = details.label;
            const body = {};
            if (legacyUpgrade) { body.legacy_upgrade = true; }
            const optionsPayload = await api(
                '/api/webauthn/register/options',
                { method: 'POST', body, headers }
            );
            const ceremony = optionsPayload.ceremony;
            delete optionsPayload.ceremony;
            const options = decodeCreationOptions(optionsPayload);
            const credential = await navigator.credentials.create({
                publicKey: options
            });
            await api('/api/webauthn/register/verify', {
                method: 'POST',
                body: {
                    ceremony,
                    name,
                    credential: serializeCredential(credential)
                }
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
        const details = await requestConfirmation({
            label: true,
            labelText: t('security.authenticatorName', 'Authenticator name'),
            labelDefault: t('security.authenticatorDefaultName', 'Authenticator'),
            hint: t('security.confirmFactorChange', 'Confirm the authenticator enrollment for this account.')
        });
        if (details === null) { return; }
        const headers = await stepUpHeaders('totp.enroll');
        if (headers === null) { return; }
        const data = await api('/api/totp/enroll', {
            method: 'POST',
            headers,
            body: { label: details.label }
        });
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
        const headers = await stepUpHeaders('mfa.disable');
        if (headers === null) { return; }
        await api('/api/account/mfa/disable', {
            method: 'POST',
            headers,
            body: { confirm_disable_mfa: true }
        });
        await loadTotpAuthenticators();
        notify(t('security.mfaDisabled', 'MFA requirement disabled'), 'success');
    }

    document.addEventListener('DOMContentLoaded', () => {
        document.getElementById('securityConfirmationForm')?.addEventListener('submit', event => {
            event.preventDefault();
            submitConfirmation();
        });
        document.getElementById('securityConfirmationClose')?.addEventListener('click', () => closeConfirmation(null));
        document.getElementById('securityConfirmationCancel')?.addEventListener('click', () => closeConfirmation(null));
        document.getElementById('securityConfirmationModal')?.addEventListener('click', event => {
            if (event.target.id === 'securityConfirmationModal') { closeConfirmation(null); }
        });
        document.addEventListener('keydown', event => {
            if (event.key === 'Escape' && confirmationRequest) { closeConfirmation(null); }
        });
        document.getElementById('hostKeyRefresh')?.addEventListener('click', () => {
            loadHostKeys().catch(error => notify(error.message, 'error'));
        });
        if (document.getElementById('hostKeyList')) {
            loadHostKeys().catch(error => notify(error.message, 'error'));
        }
        document.getElementById('recoveryGenerateBtn')?.addEventListener('click', async () => {
            try {
                const headers = await stepUpHeaders('recovery.rotate');
                if (headers === null) { return; }
                const data = await api('/api/recovery-codes', {
                    method: 'POST',
                    headers,
                    body: {}
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
        document.getElementById('recoveryDisableMfaBtn')?.addEventListener('click', async () => {
            try {
                const body = await requestConfirmation({
                    account: true,
                    hint: t('security.confirmDisableMfa', 'Disable every MFA factor?')
                });
                if (body === null) { return; }
                await api('/api/auth/mfa/disable', {
                    method: 'POST',
                    body: { confirm_username: body.account }
                });
                window.location.assign(root + '/');
            } catch (error) {
                notify(error.message, 'error');
            }
        });
        loadTotpAuthenticators().catch(error => notify(error.message, 'error'));
        document.getElementById('passkeyLoginBtn')?.addEventListener('click', async () => {
            const operation = async () => {
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
                return true;
            };
            const configuredOrigin = document.querySelector(
                'meta[name="webauthn-configured-origin"]'
            )?.content || '';
            const runner = window.WebSSHAuthUI?.createPasskeyOperationRunner?.({
                configuredOrigin,
                notify,
                translate: t,
            });
            if (runner) {
                await runner(operation);
                return;
            }
            try {
                await operation();
            } catch {
                notify(t(
                    'auth.passkeyFailed',
                    'Passkey sign-in could not be completed. Try again or use another sign-in method.',
                ), 'error');
            }
        });
    });
})();
