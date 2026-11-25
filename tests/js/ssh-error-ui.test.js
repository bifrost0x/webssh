const assert = require('node:assert/strict');
const test = require('node:test');

const { describeSSHError } = require('../../static/js/ssh-error-ui.js');


test('host-key changes get a fail-closed explanation and same-origin trust action', () => {
    const values = {
        'sshErrors.hostKeyChanged': 'Der Server zeigt einen anderen SSH-Host-Schlüssel. WebSSH hat die Verbindung blockiert.',
        'sshErrors.reviewTrust': 'SSH-Host-Vertrauen prüfen',
    };
    const result = describeSSHError(
        { code: 'host_key_changed', error: 'SSH host key changed' },
        key => values[key] || key,
        '/webssh',
    );

    assert.deepEqual(result, {
        message: values['sshErrors.hostKeyChanged'],
        type: 'error',
        duration: 12000,
        action: {
            label: values['sshErrors.reviewTrust'],
            url: '/webssh/security#ssh-host-trust',
        },
    });
});


test('generic SSH errors retain their safe server message without an action', () => {
    const result = describeSSHError(
        { error: 'Authentication failed - invalid credentials' },
        () => null,
        '',
    );

    assert.deepEqual(result, {
        message: 'SSH error: Authentication failed - invalid credentials',
        type: 'error',
        duration: undefined,
    });
});


test('a refused tailnet route explains that Tailscale SSH is required', () => {
    const values = {
        'sshErrors.tailscaleRouteRestricted': 'Dieser Host wird über das Tailnet erreicht.',
    };
    const result = describeSSHError(
        { code: 'tailscale_route_restricted', error: 'This target is on the tailnet and requires Tailscale SSH' },
        key => values[key] || key,
        '',
    );

    assert.deepEqual(result, {
        message: values['sshErrors.tailscaleRouteRestricted'],
        type: 'error',
        duration: 12000,
    });
    assert.match(
        describeSSHError({ code: 'tailscale_route_restricted' }, () => null, '').message,
        /Tailscale SSH/,
    );
});

test('a refused tailnet route names the admin setting and links to it for administrators', () => {
    const values = {
        'sshErrors.tailscaleRouteRestrictedAdmin': 'Einstellung „Normales SSH zu Tailnet-Knoten sperren“ ausschalten.',
        'sshErrors.openTailnetSetting': 'Einstellung öffnen',
    };
    const result = describeSSHError(
        { code: 'tailscale_route_restricted' },
        key => values[key] || key,
        '/webssh',
        { isAdmin: true },
    );

    assert.deepEqual(result, {
        message: values['sshErrors.tailscaleRouteRestrictedAdmin'],
        type: 'error',
        duration: 12000,
        action: { label: 'Einstellung öffnen', url: '/webssh/settings#integrations' },
    });
    const fallback = describeSSHError({ code: 'tailscale_route_restricted' }, () => null, '', { isAdmin: true });
    assert.match(fallback.message, /Block ordinary SSH to tailnet nodes/);
    assert.equal(fallback.action.url, '/settings#integrations');
    const user = describeSSHError({ code: 'tailscale_route_restricted' }, () => null, '', { isAdmin: false });
    assert.match(user.message, /ask your administrator/);
    assert.equal(user.action, undefined);
});

test('the administrator hint comes from the page and defaults to a regular user', () => {
    const previous = globalThis.document;
    try {
        globalThis.document = { querySelector: () => ({ content: 'true' }) };
        assert.ok(describeSSHError({ code: 'tailscale_route_restricted' }, () => null, '').action);
        globalThis.document = { querySelector: () => null };
        assert.equal(describeSSHError({ code: 'tailscale_route_restricted' }, () => null, '').action, undefined);
    } finally {
        if (previous === undefined) { delete globalThis.document; } else { globalThis.document = previous; }
    }
});
