const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function setup(send, connected = true) {
    const source = fs.readFileSync(path.join(__dirname, '../../static/js/app.js'), 'utf8');
    const declaration = source.indexOf('let mobileSendPending =');
    const start = declaration < 0 ? source.indexOf('const sendMobileInput =') : declaration;
    const end = source.indexOf('\n        if (mobileInput)', start);
    const session = {id: 's', host: 'alpha.example', username: 'ops', connected};
    const elements = new Map();
    const context = {mobileInput: {value: 'original'}, SessionManager: {getActiveSession: () => 's', getSession: () => session},
        window: {socket: {connected}, SSHInput: {sendText: send}},
        document: {
            addEventListener(event, callback) { if (event === 'DOMContentLoaded') callback(); },
            getElementById(id) {
                if (!elements.has(id)) elements.set(id, {dataset: {}, listeners: {}, checked: false, focus() {},
                    addEventListener(event, callback) {this.listeners[event] = callback;},
                    showModal() {this.open = true;}, close() {this.open = false;}});
                return elements.get(id);
            }
        }};
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../../static/js/terminal-paste-guard.js'), 'utf8'), context);
    vm.runInNewContext(source.slice(start, end) + '\nglobalThis.send = sendMobileInput;', context);
    return context;
}

test('mobile input remains editable after offline or rejected delivery', async () => {
    for (const connected of [false, true]) {
        const context = setup(async () => false, connected);
        await context.send();
        assert.equal(context.mobileInput.value, 'original');
    }
});

test('repeated mobile submit cannot duplicate an in-flight command and failures can retry', async () => {
    let finish;
    let calls = 0;
    const context = setup(() => { calls++; return new Promise(resolve => { finish = resolve; }); });
    const pending = context.send();
    const repeated = context.send();
    assert.equal(calls, 1);
    finish(false);
    await Promise.all([pending, repeated]);
    context.window.SSHInput.sendText = async () => { calls++; return true; };
    await context.send();
    assert.equal(calls, 2);
    assert.equal(context.mobileInput.value, '');
});

test('successful mobile delivery clears only the submitted text', async () => {
    let acknowledge;
    const context = setup(() => new Promise(resolve => { acknowledge = resolve; }));
    const pending = context.send();
    context.mobileInput.value = 'new text';
    acknowledge(true);
    await pending;
    assert.equal(context.mobileInput.value, 'new text');
    context.window.SSHInput.sendText = async () => true;
    await context.send();
    assert.equal(context.mobileInput.value, '');
});

test('mobile multiline submit sends through text transport only after review', async () => {
    const delivered = [];
    const context = setup(async (id, value) => { delivered.push([id, value]); return true; });
    context.mobileInput.value = 'first\nsecond';
    const pending = context.send();
    assert.deepEqual(delivered, []);
    assert.equal(context.document.getElementById('terminalPasteDialog').open, true);
    await context.document.getElementById('terminalPasteConfirm').listeners.click();
    await pending;
    assert.deepEqual(delivered, [['s', 'first\nsecond\r']]);
});

test('cancelled mobile review preserves the draft and sends nothing', async () => {
    const delivered = [];
    const context = setup(async (id, value) => {delivered.push([id, value]); return true;});
    context.mobileInput.value = 'first\nsecond';
    const pending = context.send();
    context.document.getElementById('terminalPasteCancel').listeners.click();
    await pending;
    assert.deepEqual(delivered, []);
    assert.equal(context.mobileInput.value, 'first\nsecond');
});
