const test = require('node:test');
const assert = require('node:assert/strict');

const {
    createRequestCoordinator,
    describeHostKey,
    downloadAuditExport
} = require('../../static/js/security-ui.js');

test('request snapshots become stale when the security modal context changes', () => {
    const coordinator = createRequestCoordinator();
    coordinator.open({ mode: 'recovery', userId: '11' });
    const first = coordinator.begin('action');

    assert.deepEqual(first.context, { mode: 'recovery', userId: '11' });
    assert.equal(Object.isFrozen(first), true);
    assert.equal(Object.isFrozen(first.context), true);
    assert.equal(coordinator.isCurrent(first), true);

    coordinator.close();
    coordinator.open({ mode: 'recovery', userId: '22' });
    const second = coordinator.begin('action');

    assert.equal(coordinator.isCurrent(first), false);
    assert.equal(coordinator.isCurrent(second), true);
    coordinator.finish(first);
    assert.equal(coordinator.isPending('action'), true);
    coordinator.finish(second);
    assert.equal(coordinator.isPending('action'), false);
});

test('request coordinator rejects duplicate actions but keeps list loading independent', () => {
    const coordinator = createRequestCoordinator();
    coordinator.open({ mode: 'oidc-link', userId: '7' });

    const action = coordinator.begin('action');
    const duplicate = coordinator.begin('action');
    const list = coordinator.begin('list');

    assert.ok(action);
    assert.equal(duplicate, null);
    assert.ok(list);
    assert.equal(coordinator.isPending('action'), true);
    assert.equal(coordinator.isPending('list'), true);
});

test('a pending sensitive action survives modal generations until it finishes', () => {
    const coordinator = createRequestCoordinator({
        persistentChannels: ['action']
    });
    coordinator.open({ mode: 'recovery', userId: '11' });
    const first = coordinator.begin('action');

    coordinator.close();
    coordinator.open({ mode: 'recovery', userId: '11' });

    assert.equal(coordinator.isCurrent(first), false);
    assert.equal(coordinator.isPending('action'), true);
    assert.equal(coordinator.begin('action'), null);
    coordinator.finish(first);
    assert.equal(coordinator.isPending('action'), false);
    assert.ok(coordinator.begin('action'));
});

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
