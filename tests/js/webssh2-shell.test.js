const test = require('node:test');
const assert = require('node:assert/strict');

const {
    buildSessionContext,
    toolAction
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

test('drawer tool tabs delegate to existing product controls', () => {
    assert.equal(toolAction('files'), 'sessionSftpToggleBtn');
    assert.equal(toolAction('commands'), 'commandLibraryBtn');
    assert.equal(toolAction('diagnostics'), 'sessionDiagnosticsToggle');
    assert.equal(toolAction('notes'), 'notepadToggle');
    assert.equal(toolAction('unknown'), null);
});
