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
    const context = {mobileInput: {value: 'original'}, SessionManager: {getActiveSession: () => 's'}, window: {socket: {connected}, SSHInput: {sendText: send}}};
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

test('mobile submit sends multiline text through the text input path', async () => {
    const delivered = [];
    const context = setup(async (id, value) => { delivered.push([id, value]); return true; });
    context.mobileInput.value = 'first\nsecond';
    await context.send();
    assert.deepEqual(delivered, [['s', 'first\nsecond\r']]);
});
