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

    return { describeHostKey, downloadAuditExport };
});
