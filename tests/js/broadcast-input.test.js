const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
function setup() {
    const delivered = [];
    const sessions = [{id: 'one', connected: true, host: 'same.example', username: 'ops'},
        {id: 'two', connected: true, host: 'same.example', username: 'ops'}];
    const elements = new Map();
    const ready = [];
    const context = {SessionManager: {getAllSessions: () => sessions, getSession: id => sessions.find(s => s.id === id)},
        window: {socket: {connected: true}, SSHInput: {sendText: async (id, text) => {delivered.push([id, text]); return true;}},
            showNotification() {}, addEventListener() {}},
        document: {addEventListener(event, callback) {if (event === 'DOMContentLoaded') ready.push(callback);},
            getElementById(id) {
                if (!elements.has(id)) elements.set(id, {dataset: {}, listeners: {}, value: '', checked: false, focus() {},
                    addEventListener(event, callback) {this.listeners[event] = callback;},
                    showModal() {this.open = true;}, close() {this.open = false;}});
                return elements.get(id);
            }}};
    for (const file of ['terminal-paste-guard.js', 'broadcast-input.js']) {
        const filePath = path.join(__dirname, '../../static/js', file);
        if (fs.existsSync(filePath)) vm.runInNewContext(fs.readFileSync(filePath, 'utf8'), context);
    }
    ready.forEach(callback => callback());
    return {api: context.window.BroadcastInput, sessions, delivered, context, element: id => context.document.getElementById(id)};
}
test('broadcast requires explicit recipients before sending', async () => {
    const {api, delivered} = setup();
    assert.equal(await api.sendAll('whoami'), 0);
    assert.deepEqual(delivered, []);
});
test('frozen broadcast selection excludes later sessions and preserves text transport', async () => {
    const {api, sessions, delivered, element} = setup();
    api.selectRecipients(['one']);
    sessions.push({id: 'later', connected: true});
    const pending = api.sendAll('first\nsecond');
    assert.deepEqual(delivered, []);
    assert.equal(element('terminalPasteDialog').open, true);
    await element('terminalPasteConfirm').listeners.click();
    assert.equal(await pending, 1);
    assert.deepEqual(delivered, [['one', 'first\nsecond\r']]);
});

test('broadcast control input is previewed and cancellation retains the draft', async () => {
    const {api, delivered, element} = setup();
    api.selectRecipients(['one', 'two']);
    element('broadcastInput').value = 'printf test\x1b[31m';
    const pending = element('broadcastSendBtn').listeners.click();
    assert.deepEqual(delivered, []);
    assert.match(element('terminalPastePreview').textContent, /\[ESC\]/);
    assert.match(element('terminalPasteTarget').textContent, /one/);
    assert.match(element('terminalPasteTarget').textContent, /two/);
    element('terminalPasteCancel').listeners.click();
    await pending;
    assert.equal(element('broadcastInput').value, 'printf test\x1b[31m');
    assert.deepEqual(delivered, []);
});

test('changing broadcast recipients cancels an outstanding approval', async () => {
    const {api, delivered, element} = setup();
    api.selectRecipients(['one', 'two']);
    const pending = api.sendAll('first\nsecond');
    assert.equal(element('terminalPasteDialog').open, true);
    api.selectRecipients(['one']);
    assert.equal(await pending, 0);
    assert.equal(element('terminalPasteDialog').open, false);
    assert.deepEqual(delivered, []);
});

test('a reconnected broadcast recipient invalidates the entire pending send', async () => {
    const {api, delivered, sessions, element, context} = setup();
    api.selectRecipients(['one', 'two']);
    const pending = api.sendAll('first\nsecond');
    sessions[1].inputGeneration = 1;
    context.window.TerminalPasteGuard.onWorkspaceChange();
    assert.equal(await pending, 0);
    assert.equal(element('terminalPasteDialog').open, false);
    assert.deepEqual(delivered, []);
});
test('one stale recipient blocks the whole broadcast, including same-id replacement', async () => {
    const {api, sessions, delivered} = setup();
    api.selectRecipients(['one', 'two']);
    sessions[1] = {...sessions[1]};
    assert.equal(await api.sendAll('dangerous'), 0);
    assert.deepEqual(delivered, []);
});
test('disconnect and reconnect never restore an earlier broadcast approval', async () => {
    const {api, sessions, delivered} = setup();
    api.selectRecipients(['one', 'two']);
    sessions[1].connected = false;
    api.updateCount();
    sessions[1].connected = true;
    assert.equal(await api.sendAll('dangerous'), 0);
    assert.deepEqual(delivered, []);
});
test('transport rejection reports only successful recipients', async () => {
    const {api, context} = setup();
    api.selectRecipients(['one', 'two']);
    context.window.SSHInput.sendText = async id => id === 'one';
    assert.equal(await api.sendAll('test'), 1);
});

test('a partial confirmed broadcast keeps its multiline draft', async () => {
    const {api, context, element} = setup();
    api.selectRecipients(['one', 'two']);
    context.window.SSHInput.sendText = async id => id === 'one';
    element('broadcastInput').value = 'first\nsecond';
    const pending = element('broadcastSendBtn').listeners.click();
    await element('terminalPasteConfirm').listeners.click();
    await pending;
    assert.equal(element('broadcastInput').value, 'first\nsecond');
});
