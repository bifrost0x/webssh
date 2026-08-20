(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (root) {
        root.WebSSHSecurityUI = api;
    }
})(typeof window !== 'undefined' ? window : globalThis, function () {
    'use strict';

    function describeHostKey(entry, translate) {
        const t = typeof translate === 'function'
            ? translate
            : (_key, fallback) => fallback;
        if (entry && entry.marker === '@revoked') {
            return {
                status: t('security.hostKeyRevoked', 'Revoked key'),
                action: t('security.removeRevocation', 'Remove revocation')
            };
        }
        if (entry && entry.marker === '@cert-authority') {
            return {
                status: t(
                    'security.certificateAuthority',
                    'Certificate authority'
                ),
                action: t('security.deleteAuthority', 'Delete authority')
            };
        }
        return {
            status: t('security.hostKeyTrusted', 'Trusted key'),
            action: t('security.deleteTrust', 'Delete trust')
        };
    }

    function hostKeyConfirmation(entry, host, translate) {
        const t = typeof translate === 'function'
            ? translate
            : (_key, fallback) => fallback;
        let key = 'security.confirmDeleteTrust';
        let fallback = 'Really delete trust for {host}?';
        if (entry && entry.marker === '@revoked') {
            key = 'security.confirmRemoveRevocation';
            fallback = 'Really remove the revocation for {host}?';
        } else if (entry && entry.marker === '@cert-authority') {
            key = 'security.confirmDeleteAuthority';
            fallback = 'Really delete the certificate authority for {host}?';
        }
        return t(key, fallback).replace('{host}', host);
    }

    function integerHeader(headers, name) {
        const value = Number.parseInt(headers.get(name) || '', 10);
        return Number.isFinite(value) ? value : null;
    }

    function featureToggleState(feature) {
        const item = feature || {};
        return {
            name: String(item.name || ''),
            checked: Boolean(item.active),
            disabled: !Boolean(item.deployment_allowed) || !Boolean(item.ready),
            reason: String(item.reason || '')
        };
    }

    function featureDisableWarning(_feature, label) {
        const name = String(label || 'this authentication feature');
        return `Disable ${name}? If this is your current sign-in method, `
            + 'you may not be able to sign in again. Existing browser, SSH, '
            + 'and tmux sessions remain available until their normal timeout; '
            + 'this change does not terminate them. New logins and factor '
            + 'setup use the new rule immediately.';
    }

    function totpAccountState(payload) {
        const item = payload || {};
        const authenticators = Array.isArray(item.authenticators)
            ? item.authenticators
            : [];
        return {
            mfaEnabled: Boolean(item.mfa_enabled),
            hasAuthenticator: authenticators.length > 0,
            canDisable: Boolean(item.mfa_enabled) && authenticators.length > 0
        };
    }

    function createAccountStepUpClient(dependencies) {
        const options = dependencies || {};
        const api = options.api;
        const requestSecret = options.requestSecret;
        const chooseMethod = options.chooseMethod;
        const getPasskeyAssertion = options.getPasskeyAssertion;
        const serializeCredential = options.serializeCredential || (value => value);
        const openAuthorization = options.openAuthorization || (url => {
            window.open(url, 'webssh-account-step-up', 'popup,width=720,height=760');
        });
        const wait = options.wait || (milliseconds => new Promise(resolve => {
            setTimeout(resolve, milliseconds);
        }));

        if (typeof api !== 'function') {
            throw new TypeError('account step-up requires an API client');
        }

        async function authorize(action, target) {
            const created = await api('/api/account/step-up/intents', {
                method: 'POST',
                body: { action, target }
            });
            if (created.grant) { return created.grant; }
            if (!created.intent || !Array.isArray(created.methods)
                    || !created.methods.includes(created.preferred_method)) {
                throw new Error('No supported authentication method is available.');
            }
            const method = created.methods.length > 1
                && typeof chooseMethod === 'function'
                ? await chooseMethod(created.methods, created.preferred_method)
                : created.preferred_method;
            if (method === null || method === undefined) { return null; }
            if (!created.methods.includes(method)) {
                throw new Error('No supported authentication method is available.');
            }
            if (method === 'password' || method === 'ldap') {
                const secret = await requestSecret(method);
                if (secret === null || secret === undefined) { return null; }
                const completed = await api(`/api/account/step-up/${method}`, {
                    method: 'POST',
                    body: { intent: created.intent, password: secret }
                });
                return completed.grant;
            }
            if (method === 'totp') {
                const secret = await requestSecret(method);
                if (secret === null || secret === undefined) { return null; }
                const completed = await api('/api/account/step-up/totp', {
                    method: 'POST',
                    body: { intent: created.intent, code: secret }
                });
                return completed.grant;
            }
            if (method === 'passkey') {
                if (typeof getPasskeyAssertion !== 'function') {
                    throw new Error('Passkey authentication is unavailable.');
                }
                const publicKey = await api(
                    '/api/account/step-up/passkey/options',
                    { method: 'POST', body: { intent: created.intent } }
                );
                const assertion = await getPasskeyAssertion(publicKey);
                const completed = await api(
                    '/api/account/step-up/passkey/verify',
                    {
                        method: 'POST',
                        body: {
                            intent: created.intent,
                            credential: serializeCredential(assertion)
                        }
                    }
                );
                return completed.grant;
            }
            if (method === 'oidc') {
                const started = await api('/api/account/step-up/oidc/start', {
                    method: 'POST',
                    body: {
                        intent: created.intent,
                        continuation: '/security'
                    }
                });
                openAuthorization(started.authorization_url);
                for (let attempt = 0; attempt < 120; attempt += 1) {
                    await wait(1000);
                    const status = await api('/api/account/step-up/status', {
                        method: 'POST',
                        body: { intent: created.intent }
                    });
                    if (status.status === 'completed' && status.grant) {
                        return status.grant;
                    }
                }
                throw new Error('Authentication confirmation timed out.');
            }
            throw new Error('No supported authentication method is available.');
        }

        return Object.freeze({
            authorize,
            header: grant => ({ 'X-WebSSH-Step-Up': grant })
        });
    }

    function createRequestCoordinator(options) {
        let generation = 0;
        let sequence = 0;
        let context = null;
        const active = new Map();
        const persistentChannels = new Set(options?.persistentChannels || []);

        function clearTransientRequests() {
            for (const channel of active.keys()) {
                if (!persistentChannels.has(channel)) {
                    active.delete(channel);
                }
            }
        }

        function open(nextContext) {
            generation += 1;
            clearTransientRequests();
            context = Object.freeze({ ...(nextContext || {}) });
            return context;
        }

        function close() {
            generation += 1;
            clearTransientRequests();
            context = null;
        }

        function begin(channel, options) {
            const replace = Boolean(options?.replace);
            if (!context || !channel || (active.has(channel) && !replace)) {
                return null;
            }
            const request = Object.freeze({
                id: ++sequence,
                generation,
                channel,
                context
            });
            active.set(channel, request.id);
            return request;
        }

        function isCurrent(request) {
            return Boolean(
                request
                && context
                && request.generation === generation
                && request.context === context
                && active.get(request.channel) === request.id
            );
        }

        function finish(request) {
            if (request && active.get(request.channel) === request.id) {
                active.delete(request.channel);
            }
        }

        function isPending(channel) {
            return active.has(channel);
        }

        function current() {
            return context;
        }

        return Object.freeze({
            begin,
            close,
            current,
            finish,
            isCurrent,
            isPending,
            open
        });
    }

    async function downloadAuditExport(url, dependencies) {
        const options = dependencies || {};
        const fetchImpl = options.fetchImpl || fetch;
        const locationRef = options.locationRef || window.location;
        const t = typeof options.translate === 'function'
            ? options.translate
            : (_key, fallback) => fallback;
        const response = await fetchImpl(url, {
            method: 'HEAD',
            credentials: 'same-origin',
            headers: { 'Accept': 'application/x-ndjson' }
        });
        if (!response.ok) {
            throw new Error(
                t('admin.auditExportFailed', 'Audit export failed ({status})')
                    .replace('{status}', response.status)
            );
        }
        const metadata = {
            truncated: (
                response.headers.get('X-WebSSH-Audit-Truncated') === 'true'
            ),
            scanned: integerHeader(
                response.headers,
                'X-WebSSH-Audit-Scanned'
            ),
            scanLimit: integerHeader(
                response.headers,
                'X-WebSSH-Audit-Scan-Limit'
            )
        };
        locationRef.assign(url);
        return metadata;
    }

    return {
        createAccountStepUpClient,
        createRequestCoordinator,
        describeHostKey,
        downloadAuditExport,
        featureDisableWarning,
        featureToggleState,
        hostKeyConfirmation,
        totpAccountState
    };
});
