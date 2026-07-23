const assert = require('node:assert/strict');
const test = require('node:test');

const manager = require('../../static/js/connection-command-manager.js');

function reset() {
    manager.mode = 'none';
    manager.freeText = '';
    manager.selectedCommandId = '';
    manager.parametersOverride = null;
    manager.selectedCommandSetId = '';
}

test('projects only the active post-connect mode into the payload', () => {
    reset();
    manager.setMode('command', false);
    manager.selectedCommandId = 'cmd-1';
    manager.parametersOverride = '--all';
    manager.selectedCommandSetId = 'stale-set';
    manager.freeText = 'stale text';

    assert.deepEqual(manager.getPayload(), {
        startup_mode: 'command',
        command_id: 'cmd-1',
        parameters_override: '--all',
    });

    manager.setMode('free_text', false);
    manager.freeText = 'pwd';
    assert.deepEqual(manager.getPayload(), {
        startup_mode: 'free_text',
        startup_commands: 'pwd',
    });
});

test('preserves the difference between default and empty command parameters', () => {
    reset();
    manager.setMode('command', false);
    manager.selectedCommandId = 'cmd-1';

    assert.deepEqual(manager.getPayload(), {
        startup_mode: 'command',
        command_id: 'cmd-1',
    });

    manager.parametersOverride = '';
    assert.deepEqual(manager.getPayload(), {
        startup_mode: 'command',
        command_id: 'cmd-1',
        parameters_override: '',
    });
});

test('infers legacy profile modes without mutating the profile', () => {
    reset();
    const legacy = { startup_commands: 'echo ready' };
    const commandSet = { command_set_id: 'set-1', startup_commands: 'fallback' };

    assert.equal(manager.inferProfileMode(legacy), 'free_text');
    assert.equal(manager.inferProfileMode(commandSet), 'command_set');
    assert.deepEqual(legacy, { startup_commands: 'echo ready' });
});

test('rerenders controls when the selected command set changes', () => {
    reset();
    const listeners = {};
    const select = {
        addEventListener(type, listener) {
            listeners[type] = listener;
        },
    };
    const originalDocument = global.document;
    const originalCommandSetManager = global.CommandSetManager;
    const originalRender = manager.render;
    let selectedId = null;
    let renderCalls = 0;

    global.document = {
        getElementById(id) {
            return id === 'commandSetSelect' ? select : null;
        },
        querySelectorAll() {
            return [];
        },
    };
    global.CommandSetManager = {
        selectForConnection(id) {
            selectedId = id;
        },
    };
    manager.render = () => {
        renderCalls += 1;
    };

    try {
        manager.init();
        renderCalls = 0;
        listeners.change({ target: { value: 'set-updates' } });

        assert.equal(manager.selectedCommandSetId, 'set-updates');
        assert.equal(selectedId, 'set-updates');
        assert.equal(renderCalls, 1);
    } finally {
        manager.render = originalRender;
        global.document = originalDocument;
        global.CommandSetManager = originalCommandSetManager;
    }
});
