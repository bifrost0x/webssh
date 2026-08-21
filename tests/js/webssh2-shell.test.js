const test = require('node:test');
const assert = require('node:assert/strict');

const {
    buildSessionContext
} = require('../../static/js/webssh2-shell.js');

test('session context is explicit and never invents connection data', () => {
    assert.deepEqual(buildSessionContext(null), {
        connected: false,
        title: 'No active session',
        host: '—',
        user: '—',
        trust: 'No connected host',
        persistence: 'Not active',
        transport: 'SSH'
    });
    assert.deepEqual(buildSessionContext({
        displayName: 'Production Edge',
        host: 'edge.example',
        port: 2222,
        username: 'ops',
        connected: true,
        hostKeyVerified: true,
        useTmux: true,
        tmuxSessionName: 'ops-main',
        viaJump: 'bastion.example'
    }), {
        connected: true,
        title: 'Production Edge',
        host: 'edge.example:2222',
        user: 'ops',
        trust: 'Host key verified',
        persistence: 'tmux · ops-main',
        transport: 'SSH via bastion.example'
    });
});

test('session context accepts localized product copy', () => {
    const translations = {
        'workspace.noActiveSession': 'Keine aktive Sitzung',
        'workspace.noConnectedHost': 'Kein verbundener Host',
        'workspace.notActive': 'Nicht aktiv',
        'workspace.connected': 'Verbunden',
        'workspace.hostKeyVerified': 'Host-Schlüssel überprüft',
        'workspace.standardSession': 'Standardsitzung',
    };
    const translate = key => translations[key] || key;

    assert.equal(buildSessionContext(null, translate).title, 'Keine aktive Sitzung');
    assert.deepEqual(
        buildSessionContext({
            host: 'edge.example',
            username: 'ops',
            connected: true,
            hostKeyVerified: true,
        }, translate),
        {
            connected: true,
            title: 'ops@edge.example',
            host: 'edge.example:22',
            user: 'ops',
            trust: 'Host-Schlüssel überprüft',
            persistence: 'Standardsitzung',
            transport: 'SSH',
        },
    );
});
