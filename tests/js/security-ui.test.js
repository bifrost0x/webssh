const test = require('node:test');
const assert = require('node:assert/strict');

const {
    createRequestCoordinator,
    describeHostKey,
    downloadAuditExport,
    featureToggleState,
    hostKeyConfirmation
} = require('../../static/js/security-ui.js');

test('feature toggles lock deployment-disabled and unready features', () => {
    assert.deepEqual(featureToggleState({
        name: 'oidc',
        deployment_allowed: false,
        ready: true,
        admin_enabled: true,
        active: false,
        reason: 'OIDC is disabled by deployment configuration.'
    }), {
        name: 'oidc',
        checked: false,
        disabled: true,
        reason: 'OIDC is disabled by deployment configuration.'
    });
    assert.deepEqual(featureToggleState({
        name: 'ldap',
        deployment_allowed: true,
        ready: false,
        admin_enabled: true,
        active: false,
        reason: 'LDAP is not ready.'
    }), {
        name: 'ldap',
        checked: false,
        disabled: true,
        reason: 'LDAP is not ready.'
    });
});

test('ready feature toggles remain editable when admin-disabled', () => {
    assert.deepEqual(featureToggleState({
        name: 'totp',
        deployment_allowed: true,
        ready: true,
        admin_enabled: false,
        active: false,
        reason: 'TOTP is not activated in the admin panel.'
    }), {
        name: 'totp',
        checked: false,
        disabled: false,
        reason: 'TOTP is not activated in the admin panel.'
    });
});

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
        action: 'Remove revocation'
    });
    assert.deepEqual(describeHostKey({ marker: null }), {
        status: 'Trusted key',
        action: 'Delete trust'
    });
    assert.equal(
        hostKeyConfirmation({ marker: '@revoked' }, 'example.com:22'),
        'Really remove the revocation for example.com:22?'
    );
    assert.equal(
        hostKeyConfirmation({ marker: null }, 'example.com:22'),
        'Really delete trust for example.com:22?'
    );
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
