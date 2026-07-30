const test = require('node:test');
const assert = require('node:assert/strict');

const {
    describeHostKey,
    downloadAuditExport
} = require('../../static/js/security-ui.js');

test('revoked host keys are presented as revocations, not trust records', () => {
    assert.deepEqual(describeHostKey({ marker: '@revoked' }), {
        status: 'Revoked key',
        action: 'Remove revocation',
        confirmationAction: 'remove the revocation for'
    });
    assert.deepEqual(describeHostKey({ marker: null }), {
        status: 'Trusted key',
        action: 'Delete trust',
        confirmationAction: 'delete trust for'
    });
});

test('audit export checks metadata before starting a native download', async () => {
    const navigated = [];
    const headers = new Map([
        ['X-WebSSH-Audit-Truncated', 'true'],
        ['X-WebSSH-Audit-Scanned', '50000'],
        ['X-WebSSH-Audit-Scan-Limit', '50000']
    ]);
    const response = {
        ok: true,
        headers: { get: name => headers.get(name) || null }
    };
    const result = await downloadAuditExport('/export', {
        fetchImpl: async (url, options) => {
            assert.equal(url, '/export');
            assert.equal(options.method, 'HEAD');
            assert.equal(options.credentials, 'same-origin');
            return response;
        },
        locationRef: {
            assign: url => navigated.push(url)
        }
    });

    assert.deepEqual(navigated, ['/export']);
    assert.deepEqual(result, {
        truncated: true,
        scanned: 50000,
        scanLimit: 50000
    });
});
