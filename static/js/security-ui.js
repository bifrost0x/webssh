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
        createRequestCoordinator,
        describeHostKey,
        downloadAuditExport,
        featureToggleState,
        hostKeyConfirmation
    };
});
