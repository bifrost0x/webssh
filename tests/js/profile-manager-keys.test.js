const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

function loadProfileManager(overrides = {}) {
    const source = fs.readFileSync(path.join(__dirname, '../../static/js/profile-manager.js'), 'utf8');
    const timers = [];
    const context = {
        window: {},
        setTimeout: (fn, delay) => { timers.push({fn, delay}); return timers.length; },
        clearTimeout: () => {},
        confirm: () => true,
        ...overrides,
    };
    vm.createContext(context);
    vm.runInContext(source, context);
    const manager = context.window.ProfileManager;
    manager.renderKeySelect = () => {};
    manager.renderKeysList = () => {};
    manager.renderEditorSelects = () => {};
    manager.refreshEmptyPanes = () => {};
    manager.t = (_key, fallback) => fallback;
    return {manager, window: context.window, timers};
}

const settle = () => new Promise(resolve => setImmediate(resolve));

test('a refused key list is retried and reported instead of waiting forever', () => {
    const {manager, window, timers} = loadProfileManager();
    const sent = [];
    let answer = {success: false, error: 'Too many attempts. Try again later.', code: 'rate_limited', retry_after_ms: 1500};
    window.socket = {emit(event, ack) { sent.push(event); ack(answer); }};

    manager.loadKeys();
    assert.deepEqual(sent, ['list_keys']);
    assert.equal(manager.keysLoaded, false);
    assert.equal(manager.keysLoadFailed, true);
    assert.equal(timers.length, 1);
    assert.equal(timers[0].delay, 1750, 'the server hint decides the delay');

    // Without a hint the delay grows and is bounded.
    answer = {success: false, error: 'Too many SSH key list requests. Please wait a moment.'};
    timers.shift().fn();
    assert.equal(timers.at(-1).delay, 4000);
    for (let i = 0; i < 10; i += 1) timers.shift()?.fn();
    assert.ok(timers.length === 0, 'automatic retries stop');
    assert.equal(sent.length, 7, 'one request and six retries');
    assert.equal(manager.keysLoadFailed, true);

    // An explicit load starts again and success clears the failure.
    window.socket = {emit(event, ack) { sent.push(event); manager.setKeys([{id: 'k', name: 'K', key_type: 'RSA', usable: true}]); ack(undefined); }};
    manager.renderKeySelect = () => {};
    manager.loadKeys();
    assert.equal(manager.keysLoaded, true);
    assert.equal(manager.keysLoadFailed, false);
    assert.equal(manager.keyLoadAttempts, 0);
});

test('the Python acknowledgement of a successful list is not a failure', () => {
    const {manager, window, timers} = loadProfileManager();
    window.socket = {emit(_event, ack) { ack(); }};
    manager.loadKeys();
    assert.equal(manager.keysLoadFailed, false);
    assert.equal(timers.length, 0);
});

test('a key change without challenge is sent once, as the Python release expects', async () => {
    const {manager, window} = loadProfileManager();
    const sent = [];
    window.socket = {emit(event, payload, ack) { sent.push({event, payload}); ack({success: false, error: 'Invalid key format'}); }};
    let authorized = false;
    manager.authorizeKeyChange = async () => { authorized = true; return 'g'; };
    const ack = await manager.sendKeyChange('upload_key', {name: 'k', key_content: 'x'}, {action: 'key.upload'});
    assert.equal(ack.error, 'Invalid key format');
    assert.equal(sent.length, 1);
    assert.deepEqual(JSON.parse(JSON.stringify(sent[0].payload)), {name: 'k', key_content: 'x'});
    assert.equal(authorized, false);
});

test('step-up and passphrase are asked once each and the change is sent again', async () => {
    const {manager, window} = loadProfileManager();
    const sent = [];
    const answers = [
        {success: false, code: 'step_up_required', error: 'Confirm your identity to continue.'},
        {success: false, code: 'invalid_value', passphrase_required: true, error: 'This private key is protected by a passphrase.'},
        {success: true, key: {id: 'k1', name: 'k', key_type: 'Ed25519', usable: true}},
    ];
    window.socket = {emit(event, payload, ack) { sent.push(JSON.parse(JSON.stringify(payload))); ack(answers.shift()); }};
    const asked = [];
    manager.authorizeKeyChange = async (action, target) => { asked.push(['step-up', action, target]); return 'grant-1'; };
    manager.requestKeyPassphrase = async message => { asked.push(['passphrase', message]); return 'secret'; };

    const ack = await manager.sendKeyChange('replace_key', {key_id: 'k1', key_content: 'pem'}, {action: 'key.replace', target: 'k1'});
    assert.equal(ack.success, true);
    assert.deepEqual(asked, [['step-up', 'key.replace', 'k1'], ['passphrase', 'This private key is protected by a passphrase.']]);
    assert.deepEqual(sent, [
        {key_id: 'k1', key_content: 'pem'},
        {key_id: 'k1', key_content: 'pem', step_up: 'grant-1'},
        {key_id: 'k1', key_content: 'pem', step_up: 'grant-1', passphrase: 'secret'},
    ]);
});

test('a second step-up refusal is returned, not looped', async () => {
    const {manager, window} = loadProfileManager();
    let sends = 0;
    window.socket = {emit(_e, _p, ack) { sends += 1; ack({success: false, code: 'step_up_required', error: 'Confirm your identity to continue.'}); }};
    let steps = 0;
    manager.authorizeKeyChange = async () => { steps += 1; return 'g'; };
    const ack = await manager.sendKeyChange('delete_key', {key_id: 'k1'}, {action: 'key.delete', target: 'k1'});
    assert.equal(ack.code, 'step_up_required');
    assert.equal(sends, 2);
    assert.equal(steps, 1);
});

test('wrong passphrases end after a bounded number of attempts', async () => {
    const {manager, window} = loadProfileManager();
    let sends = 0;
    window.socket = {emit(_e, _p, ack) { sends += 1; ack({success: false, passphrase_required: true, error: 'The passphrase does not match the private key.'}); }};
    manager.requestKeyPassphrase = async () => 'wrong';
    const ack = await manager.sendKeyChange('upload_key', {name: 'k', key_content: 'pem'}, {action: 'key.upload'});
    assert.equal(ack.success, false);
    assert.equal(sends, 5);
});

test('cancelling the confirmation reports that nothing changed', async () => {
    const {manager, window} = loadProfileManager();
    const notices = [];
    window.showNotification = (text, kind) => notices.push([text, kind]);
    window.socket = {emit(_e, _p, ack) { ack({success: false, code: 'step_up_required', error: 'Confirm your identity to continue.'}); }};
    manager.authorizeKeyChange = async () => null;
    manager.uploadKey('k', 'pem');
    await settle();
    assert.deepEqual(notices, [['The SSH key was not changed.', 'error']]);

    // Delete reports its own cancellation, since nothing else does.
    notices.length = 0;
    manager.deleteKey('k1');
    await settle();
    assert.deepEqual(notices, [['The SSH key was not changed.', 'error']]);
});

test('the step-up uses the account step-up client with the key action and target', async () => {
    const calls = [];
    const {manager, window} = loadProfileManager();
    window.WebSSHSecurityUI = {
        createAccountStepUpClient(deps) {
            assert.equal(typeof deps.api, 'function');
            assert.equal(typeof deps.requestSecret, 'function');
            assert.equal(typeof deps.chooseMethod, 'function');
            return {authorize: async (action, target) => { calls.push([action, target]); return 'grant'; }};
        },
    };
    assert.equal(await manager.authorizeKeyChange('key.upload', undefined), 'grant');
    assert.equal(await manager.authorizeKeyChange('key.delete', 'k1'), 'grant');
    assert.deepEqual(calls, [['key.upload', undefined], ['key.delete', 'k1']]);

    window.WebSSHSecurityUI = {createAccountStepUpClient: () => ({authorize: async () => { throw new Error('No supported authentication method is available.'); }})};
    const notices = [];
    window.showNotification = text => notices.push(text);
    assert.equal(await manager.authorizeKeyChange('key.upload'), null);
    assert.deepEqual(notices, ['No supported authentication method is available.']);
});

test('the key list waits for the realtime connection instead of failing before it', () => {
    const {manager, window, timers} = loadProfileManager();
    const sent = [];
    const listeners = [];
    window.socket = {
        connected: false,
        emit(event, ack) { sent.push(event); manager.setKeys([]); ack(undefined); },
        once(event, fn) { listeners.push({event, fn}); },
    };
    manager.loadKeys();
    manager.loadKeys();
    assert.deepEqual(sent, [], 'nothing is sent before the connection is up');
    assert.equal(listeners.length, 1, 'repeated loads wait on one listener');
    assert.equal(listeners[0].event, 'connect');
    assert.equal(manager.keysLoadFailed, false);
    assert.equal(timers.length, 0, 'no retry timer: the request is not refused');
    window.socket.connected = true;
    listeners[0].fn();
    assert.deepEqual(sent, ['list_keys']);
    assert.equal(manager.keysLoaded, true);
});
