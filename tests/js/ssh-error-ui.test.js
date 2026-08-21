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
