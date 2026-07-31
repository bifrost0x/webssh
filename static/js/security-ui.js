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

    function describeHostKey(entry) {
        if (entry && entry.marker === '@revoked') {
            return {
                status: 'Revoked key',
                action: 'Remove revocation',
                confirmationAction: 'remove the revocation for'
            };
        }
        if (entry && entry.marker === '@cert-authority') {
            return {
                status: 'Certificate authority',
                action: 'Delete authority',
                confirmationAction: 'delete the certificate authority for'
            };
        }
        return {
            status: 'Trusted key',
            action: 'Delete trust',
            confirmationAction: 'delete trust for'
        };
    }

    function integerHeader(headers, name) {
        const value = Number.parseInt(headers.get(name) || '', 10);
        return Number.isFinite(value) ? value : null;
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
        const response = await fetchImpl(url, {
            method: 'HEAD',
            credentials: 'same-origin',
            headers: { 'Accept': 'application/x-ndjson' }
        });
        if (!response.ok) {
            throw new Error(`Audit export failed (${response.status})`);
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
        downloadAuditExport
    };
});
