(function () {
    'use strict';

    const root = (document.querySelector('meta[name="app-root"]')?.content || '').replace(/\/$/, '');
    const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
    const recoveryMode = document.body?.dataset.recoveryMode === 'true';
    let accountMfaEnabled = document.body?.dataset.accountMfaEnabled === 'true';
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
            github: t('security.methodGithub', 'GitHub'),
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

    function factorRow(labelText, createdAt, deleteLabel, onDelete) {
        const row = document.createElement('div');
        row.className = 'security-factor-row';
        const details = document.createElement('div');
        details.className = 'security-factor-details';
        const label = document.createElement('strong');
        label.textContent = labelText;
        const created = document.createElement('time');
        created.dateTime = createdAt;
        created.textContent = new Date(createdAt).toLocaleString();
        details.append(label, created);
        const button = document.createElement('button');
        button.className = 'btn btn-danger';
        button.textContent = t('common.delete', 'Delete');
        button.setAttribute(
            'aria-label',
            `${t('common.delete', 'Delete')} ${deleteLabel}`
        );
        button.addEventListener('click', onDelete);
        row.append(details, button);
        return row;
    }

    async function loadAccountSecurityState() {
        const badge = document.getElementById('securityMfaStatus');
        if (!badge) { return null; }
        const state = await api('/api/account/security-state');
        accountMfaEnabled = Boolean(state.mfa_enabled);
        document.body.dataset.accountMfaEnabled = String(accountMfaEnabled);
        badge.classList.toggle('active', accountMfaEnabled);
        badge.dataset.i18n = accountMfaEnabled
            ? 'security.mfaEnabled'
            : 'security.mfaOptional';
        badge.textContent = accountMfaEnabled
            ? t('security.mfaEnabled', 'MFA enabled')
            : t('security.mfaOptional', 'MFA optional');

        const extraProtection = document.getElementById(
            'securityExtraProtectionState'
        );
        if (extraProtection) {
            extraProtection.dataset.i18n = accountMfaEnabled
                ? 'security.extraProtectionEnabled'
                : 'security.extraProtectionOptional';
            extraProtection.textContent = accountMfaEnabled
                ? t(
                    'security.extraProtectionEnabled',
                    'A registered strong factor is required for protected changes.'
                )
                : t(
                    'security.extraProtectionOptional',
                    'Passkeys and authenticator apps are optional for this account.'
                );
        }
        document.getElementById('passkeyEnableMfaBtn')?.classList.toggle(
            'hidden',
            !state.can_enable_mfa
        );
        document.getElementById('accountDisableMfaBtn')?.classList.toggle(
            'hidden',
            !state.can_disable_mfa
        );
        return state;
    }

    async function refreshSecuritySurface() {
        await Promise.all([
            loadAccountSecurityState(),
            loadPasskeys(),
            loadTotpAuthenticators()
        ]);
    }

    async function loadPasskeys() {
        const container = document.getElementById('passkeyList');
        if (!container || !document.getElementById('passkeyAddBtn')) { return; }
        const data = await api('/api/webauthn/credentials');
        const credentials = data.credentials || [];
        container.replaceChildren();
        if (credentials.length === 0) {
            const empty = document.createElement('p');
            empty.className = 'admin-muted security-factor-empty';
            empty.textContent = t(
                'security.noPasskeys',
                'No passkey is registered.'
            );
            container.appendChild(empty);
            return;
        }
        for (const credential of credentials) {
            container.appendChild(factorRow(
                credential.name,
                credential.created_at,
                credential.name,
                async () => {
                    try {
                        if (!window.confirm(t(
                            'security.confirmDeletePasskey',
                            'Delete this passkey? Make sure another sign-in method remains available.'
                        ))) { return; }
                        const headers = await stepUpHeaders(
                            'passkey.delete',
                            credential.id
                        );
                        if (headers === null) { return; }
                        await api(`/api/webauthn/credentials/${credential.id}`, {
                            method: 'DELETE',
                            headers
                        });
                        await refreshSecuritySurface();
                    } catch (error) {
                        notify(error.message, 'error');
                    }
                }
            ));
        }
    }

    async function enablePasskeyMfa() {
        if (!window.confirm(t(
            'security.confirmEnablePasskeyMfa',
            'Require a Passkey, authenticator app, or recovery code after every password or directory sign-in?'
        ))) { return; }
        const headers = await stepUpHeaders('mfa.enable');
        if (headers === null) { return; }
        const data = await api('/api/webauthn/mfa', {
            method: 'POST',
            headers,
            body: {confirm_enable_mfa: true}
        });
        const codes = data.recovery_codes || [];
        if (codes.length) {
            document.getElementById('passkeyMfaRecoveryCodes').textContent = [
                t(
                    'security.storeRecoveryCodes',
                    'Store these codes now. They will not be shown again.'
                ),
                '',
                ...codes
            ].join('\n');
        }
        await refreshSecuritySurface();
        notify(t('security.mfaEnabled', 'MFA enabled'), 'success');
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
            await refreshSecuritySurface();
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
        const authenticators = data.authenticators || [];
        container.replaceChildren();
        for (const authenticator of authenticators) {
            container.appendChild(factorRow(
                authenticator.label,
                authenticator.created_at,
                authenticator.label,
                async () => {
                    try {
                        if (!window.confirm(t(
                            'security.confirmDeleteAuthenticator',
                            'Delete this authenticator app?'
                        ))) { return; }
                        const headers = await stepUpHeaders(
                            'totp.delete',
                            authenticator.id
                        );
                        if (headers === null) { return; }
                        await api(
                            `/api/totp/authenticators/${authenticator.id}`,
                            { method: 'DELETE', headers }
                        );
                        await refreshSecuritySurface();
                        notify(t(
                            'security.authenticatorDeleted',
                            'Authenticator app deleted'
                        ), 'success');
                    } catch (error) {
                        notify(error.message, 'error');
                    }
                }
            ));
        }
        if (authenticators.length === 0) {
            const empty = document.createElement('p');
            empty.className = 'admin-muted security-factor-empty';
            empty.textContent = t(
                'security.noTotpAuthenticators',
                'No authenticator app is enrolled.'
            );
            container.appendChild(empty);
        }
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
        await refreshSecuritySurface();
        notify(t('security.mfaEnabled', 'MFA enabled'), 'success');
    }

    async function disableAccountMfa() {
        if (!window.confirm(t(
            'security.confirmDisableMfaAndRemoveTotp',
            'Disable MFA and remove all authenticator apps? This cannot be undone.'
        ))) { return; }
        const headers = await stepUpHeaders('mfa.disable');
        if (headers === null) { return; }
        await api('/api/account/mfa/disable', {
            method: 'POST',
            headers,
            body: { confirm_disable_mfa: true }
        });
        await refreshSecuritySurface();
        notify(t('security.mfaDisabled', 'MFA requirement disabled'), 'success');
    }

    function renderGitHubIdentity() {
        const button = document.getElementById('githubIdentityAction');
        const status = document.getElementById('githubIdentityStatus');
        if (!button || !status) { return; }
        const connected = button.dataset.connected === 'true';
        const actionLabel = button.querySelector('.github-identity-action-label');
        const label = connected
            ? t('security.disconnectGithub', 'Disconnect GitHub')
            : t('security.connectGithub', 'Connect GitHub');
        if (actionLabel) {
            actionLabel.textContent = label;
        } else {
            button.textContent = label;
        }
        status.textContent = connected
            ? t('security.githubConnectedAs', 'Connected as {login}')
                .replace('{login}', button.dataset.githubLogin || '')
            : t('security.githubNotConnected', 'Not connected');
    }

    async function loadGitHubIdentity() {
        const button = document.getElementById('githubIdentityAction');
        const status = document.getElementById('githubIdentityStatus');
        if (!button || !status) { return; }
        const data = await api('/api/account/github');
        const identity = data.identity;
        button.dataset.connected = identity ? 'true' : 'false';
        button.dataset.githubLogin = identity?.login || '';
        renderGitHubIdentity();
    }

    async function changeGitHubIdentity() {
        const button = document.getElementById('githubIdentityAction');
        if (!button) { return; }
        const userId = Number.parseInt(
            document.querySelector('meta[name="current-user-id"]')?.content || '',
            10
        );
        if (!Number.isInteger(userId)) {
            throw new Error(t(
                'security.accountIdentityUnavailable',
                'Account identity is unavailable'
            ));
        }
        if (button.dataset.connected === 'true') {
            if (!window.confirm(t(
                'security.disconnectGithubConfirm',
                'Disconnect this GitHub identity from your WebSSH account?'
            ))) { return; }
            const headers = await stepUpHeaders('github.unlink', userId);
            if (headers === null) { return; }
            await api('/api/account/github', { method: 'DELETE', headers });
            await loadGitHubIdentity();
            notify(t('security.githubDisconnected', 'GitHub disconnected'), 'success');
            return;
        }
        const headers = await stepUpHeaders('github.link', userId);
        if (headers === null) { return; }
        const started = await api('/api/account/github/link/start', {
            method: 'POST', headers, body: {}
        });
        window.location.assign(started.authorization_url);
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
        document.getElementById('githubIdentityAction')?.addEventListener('click', () => {
            changeGitHubIdentity().catch(error => notify(error.message, 'error'));
        });
        window.addEventListener('languageChanged', renderGitHubIdentity);
        loadGitHubIdentity().catch(error => notify(error.message, 'error'));
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
        document.getElementById('passkeyEnableMfaBtn')?.addEventListener('click', () => {
            enablePasskeyMfa().catch(error => notify(error.message, 'error'));
        });
        document.getElementById('accountDisableMfaBtn')?.addEventListener('click', () => {
            disableAccountMfa().catch(error => notify(error.message, 'error'));
        });
        document.getElementById('totpAddBtn')?.addEventListener('click', () => {
            beginTotpEnrollment().catch(error => notify(error.message, 'error'));
        });
        document.getElementById('totpActivateBtn')?.addEventListener('click', () => {
            activateTotpEnrollment().catch(error => notify(error.message, 'error'));
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
        refreshSecuritySurface().catch(error => notify(error.message, 'error'));
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
