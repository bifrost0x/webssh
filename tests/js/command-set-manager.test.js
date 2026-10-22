const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

function harness() {
    const listeners = new Map();
    const requests = [];
    const notifications = [];
    const source = {id: 'original', name: 'Original', steps: [{type: 'inline', command: 'printf original'}]};
    const copy = {...source, id: 'copy', name: 'Original Copy'};
    let serverSets = [source];
    let acknowledge;
    let menuOpen = false;
    let renders = 0;
    const window = {
        addEventListener() {},
        showNotification: (...args) => notifications.push(args),
        socket: {
            on: (event, handler) => listeners.set(event, handler),
            emit(event, payload, callback) {
                requests.push(event);
                if (event === 'duplicate_command_set') acknowledge = callback;
                if (event === 'list_command_sets') {
                    listeners.get('command_sets_list')({success: true, command_sets: serverSets});
                }
            },
        },
    };
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../../static/js/command-set-manager.js'), 'utf8'), {
        window,
        document: {getElementById: () => null, querySelectorAll: () => []},
    });
    const manager = window.CommandSetManager;
    manager.renderSelect = () => {};
    manager.renderPreview = () => {};
    // Rebuilding the real management list replaces its closed <details> nodes.
    manager.renderManagementList = () => { menuOpen = false; renders++; };
    manager.init();
    requests.length = 0;
    renders = 0;
    return {
        manager, source, copy, requests, notifications,
        publishDuplicate() {
            serverSets = [source, copy];
            listeners.get('command_sets_list')({success: true, command_sets: serverSets});
        },
        acknowledge: result => acknowledge(result),
        openMenu: () => { menuOpen = true; },
        menuOpen: () => menuOpen,
        renders: () => renders,
    };
}

test('duplicate acknowledgement preserves the authoritative pushed list and already opened actions', () => {
    const state = harness();
    state.manager.duplicate(state.source.id);
    // The server sends its updated list before the duplicate acknowledgement.
    state.publishDuplicate();
    assert.equal(state.manager.getById(state.copy.id), state.copy);
    state.openMenu();
    state.acknowledge({success: true, command_set: state.copy});
    assert.equal(state.menuOpen(), true, 'the ACK must not trigger a second list replacement');
    assert.equal(state.renders(), 1);
    assert.deepEqual(state.requests, ['duplicate_command_set']);
    assert.equal(state.manager.getById(state.copy.id), state.copy);
});

test('a rejected duplicate acknowledgement still reports its error without reloading the list', () => {
    const state = harness();
    state.manager.duplicate(state.source.id);
    state.acknowledge({success: false, error: 'Duplicate rejected'});
    assert.deepEqual(state.notifications, [['Duplicate rejected', 'error']]);
    assert.deepEqual(state.requests, ['duplicate_command_set']);
    assert.equal(state.manager.getById(state.source.id), state.source);
    assert.equal(state.manager.getById(state.copy.id), null);
});
