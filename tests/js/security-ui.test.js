const test = require('node:test');
const assert = require('node:assert/strict');

const {
    createAccountStepUpClient,
    createRequestCoordinator,
    describeHostKey,
    downloadAuditExport,
    featureToggleState,
    featureDisableWarning,
    hostKeyConfirmation,
    totpAccountState
} = require('../../static/js/security-ui.js');

test('feature disable warning explains self-lockout and session fallback', () => {
    const warning = featureDisableWarning({ name: 'oidc' }, 'OpenID Connect');

    assert.match(warning, /may not be able to sign in again/i);
    assert.match(warning, /remain available until their normal timeout/i);
    assert.match(warning, /New logins and factor setup/i);
});

test('account step-up follows the authentication source selected by the server', async () => {
    const calls = [];
    const client = createAccountStepUpClient({
        api: async (path, options) => {
            calls.push([path, options]);
            if (path.endsWith('/intents')) {
                return {
                    intent: 'intent-ldap',
                    preferred_method: 'ldap',
                    methods: ['ldap']
                };
            }
            return { grant: 'grant-ldap' };
        },
        requestSecret: async method => {
            assert.equal(method, 'ldap');
            return 'directory-password';
        }
    });

    const grant = await client.authorize('passkey.enroll', 17);

    assert.equal(grant, 'grant-ldap');
    assert.deepEqual(calls.map(item => item[0]), [
        '/api/account/step-up/intents',
        '/api/account/step-up/ldap'
    ]);
    assert.deepEqual(calls[1][1].body, {
        intent: 'intent-ldap',
        password: 'directory-password'
    });
});

test('OIDC account step-up never asks for a local password', async () => {
    let secretRequests = 0;
    const opened = [];
    let polls = 0;
    const client = createAccountStepUpClient({
        api: async path => {
            if (path.endsWith('/intents')) {
                return {
                    intent: 'intent-oidc',
                    preferred_method: 'oidc',
                    methods: ['oidc']
                };
            }
            if (path.endsWith('/oidc/start')) {
                return { authorization_url: 'https://idp.example/authorize' };
            }
            polls += 1;
            return polls === 1
                ? { status: 'pending' }
                : { status: 'completed', grant: 'grant-oidc' };
        },
        requestSecret: async () => {
            secretRequests += 1;
            return 'must-not-be-used';
        },
        openAuthorization: url => opened.push(url),
        wait: async () => {}
    });

    assert.equal(await client.authorize('recovery.rotate', 17), 'grant-oidc');
    assert.equal(secretRequests, 0);
    assert.deepEqual(opened, ['https://idp.example/authorize']);
    assert.equal(polls, 2);
});

test('passkey step-up serializes the assertion and returns an exact grant header', async () => {
    const calls = [];
    const client = createAccountStepUpClient({
        api: async (path, options) => {
            calls.push([path, options]);
            if (path.endsWith('/intents')) {
                return {
                    intent: 'intent-passkey',
                    preferred_method: 'passkey',
                    methods: ['passkey']
                };
            }
            if (path.endsWith('/passkey/options')) {
                return { challenge: 'challenge' };
            }
            return { grant: 'grant-passkey' };
        },
        getPasskeyAssertion: async options => ({ options }),
        serializeCredential: assertion => ({ serialized: assertion })
    });

    const grant = await client.authorize('passkey.delete', 42);

    assert.equal(grant, 'grant-passkey');
    assert.deepEqual(calls[2][1].body, {
        intent: 'intent-passkey',
        credential: {
            serialized: { options: { challenge: 'challenge' } }
        }
    });
    assert.deepEqual(client.header(grant), {
        'X-WebSSH-Step-Up': 'grant-passkey'
    });
});

test('account step-up lets the user choose an available strong method', async () => {
    const calls = [];
    const client = createAccountStepUpClient({
        api: async (path, options) => {
            calls.push([path, options]);
            if (path.endsWith('/intents')) {
                return {
                    intent: 'intent-mfa',
                    preferred_method: 'oidc',
                    methods: ['oidc', 'passkey', 'totp']
                };
            }
            return { grant: 'grant-totp' };
        },
        chooseMethod: async (methods, preferred) => {
            assert.deepEqual(methods, ['oidc', 'passkey', 'totp']);
            assert.equal(preferred, 'oidc');
            return 'totp';
        },
        requestSecret: async method => {
            assert.equal(method, 'totp');
            return '123456';
        }
    });

    assert.equal(await client.authorize('recovery.rotate', 17), 'grant-totp');
    assert.equal(calls[1][0], '/api/account/step-up/totp');
});

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

test('TOTP account state only offers explicit disable for enabled accounts', () => {
    assert.deepEqual(totpAccountState({
        mfa_enabled: true,
        authenticators: [{ id: 1 }]
    }), {
        mfaEnabled: true,
        hasAuthenticator: true,
        canDisable: true
    });
    assert.deepEqual(totpAccountState({
        mfa_enabled: false,
        authenticators: []
    }), {
        mfaEnabled: false,
        hasAuthenticator: false,
        canDisable: false
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
