const assert = require('node:assert/strict');
const test = require('node:test');

const launcher = require('../../static/js/session-command-launcher.js');

const commands = [
    {
        id: 'cmd-1',
        name: 'Service status',
        command: 'systemctl status',
        parameters: 'webssh',
        description: 'Show the service state',
    },
    {
        id: 'cmd-multiline',
        name: 'Unsafe paste',
        command: 'echo one\necho two',
        parameters: '',
        description: 'Contains a line break',
    },
];

const commandSets = [
    {
        id: 'set-1',
        name: 'Release checks',
        description: 'Inspect the deployment',
        resolved_command: 'git status && systemctl status webssh',
    },
    {
        id: 'set-broken',
        name: 'Missing command',
        description: 'No longer resolves',
        resolution_error: 'Command no longer exists',
    },
];

test('builds one searchable model with command sets before commands', () => {
    const all = launcher.buildLauncherEntries(commands, commandSets, 'status');

    assert.deepEqual(all.map(item => [item.type, item.id]), [
        ['set', 'set-1'],
        ['command', 'cmd-1'],
    ]);
    assert.equal(all[0].insertText, commandSets[0].resolved_command);
    assert.equal(all[1].insertText, 'systemctl status webssh');
});

test('keeps unsafe or unresolved entries visible but unavailable', () => {
    const entries = launcher.buildLauncherEntries(commands, commandSets, '');
    const multiline = entries.find(item => item.id === 'cmd-multiline');
    const unresolved = entries.find(item => item.id === 'set-broken');

    assert.equal(multiline.available, false);
    assert.equal(multiline.unavailableReason, 'multiline');
    assert.equal(unresolved.available, false);
    assert.equal(unresolved.unavailableReason, 'unresolved');
});

test('inserts exact text into the bound connected session without Enter', () => {
    const emissions = [];
    const events = [];
    const controller = launcher.createSessionCommandController({
        getSession: sessionId => (
            sessionId === 'session-a' ? { connected: true, name: 'Production Edge' } : null
        ),
        getCommands: () => commands,
        getCommandSets: () => commandSets,
        emitInput: (sessionId, text) => emissions.push({ sessionId, text }),
        focusSession: sessionId => events.push(['focus', sessionId]),
        close: () => events.push(['close']),
        notify: (message, type) => events.push(['notify', message, type]),
        insertedMessage: sessionName => `Inserted into ${sessionName}`,
    });

    const result = controller.insert('session-a', 'set', 'set-1');

    assert.equal(result.ok, true);
    assert.deepEqual(emissions, [{
        sessionId: 'session-a',
        text: 'git status && systemctl status webssh',
    }]);
    assert.equal(/[\r\n]/.test(emissions[0].text), false);
    assert.deepEqual(events, [
        ['close'],
        ['focus', 'session-a'],
        ['notify', 'Inserted into Production Edge', 'success'],
    ]);
});

test('refuses stale, disconnected, and multiline targets', () => {
    const emissions = [];
    const controller = launcher.createSessionCommandController({
        getSession: sessionId => (
            sessionId === 'offline' ? { connected: false, name: 'Offline' } : null
        ),
        getCommands: () => commands,
        getCommandSets: () => commandSets,
        emitInput: (sessionId, text) => emissions.push({ sessionId, text }),
    });

    assert.equal(controller.insert('missing', 'command', 'cmd-1').ok, false);
    assert.equal(controller.insert('offline', 'command', 'cmd-1').ok, false);
    assert.equal(controller.insert('offline', 'command', 'cmd-multiline').ok, false);
    assert.deepEqual(emissions, []);
});
