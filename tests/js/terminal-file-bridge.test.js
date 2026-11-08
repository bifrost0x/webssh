const test = require('node:test');
const assert = require('node:assert/strict');
const bridge = require('../../static/js/terminal-file-bridge.js');

test('folder paths require absolute paths, without shell expansion or controls', () => {
    assert.equal(bridge.validPath('/var/log/my app'), true);
    for (const path of ['.', '~/logs', 'logs', '/tmp\nwhoami', '/tmp\x1b[1m', '/tmp\x00']) {
        assert.equal(bridge.validPath(path), false, JSON.stringify(path));
    }
});
test('file paths are quoted as a single POSIX argument, never a command', () => {
    assert.equal(bridge.quotePath("/tmp/a'$(id);b"), "'/tmp/a'\"'\"'$(id);b'");
    assert.equal(bridge.quotePath('/tmp\rnext'), null);
});
test('insertion is bound to the source SSH session and cannot fall back to active session', async () => {
    const sent = [];
    const deps = { getSession: id => id === 'one' ? { connected: true } : null,
        send: (...args) => { sent.push(args); return Promise.resolve(true); } };
    assert.equal(await bridge.insertPath(deps, 'sftp-session:one', '/tmp/file'), true);
    assert.deepEqual(sent, [['one', "'/tmp/file'"]]);
    assert.equal(await bridge.insertPath(deps, 'sftp-session:two', '/tmp/file'), false);
    assert.equal(await bridge.insertPath(deps, 'smb:one', '/tmp/file'), false);
    assert.equal(await bridge.insertPath(deps, 'sftp-quick:one', '/tmp/file'), false);
    assert.equal(sent.length, 1);
});
test('failed transport is not reported as successful insertion', async () => {
    assert.equal(await bridge.insertPath({getSession: () => ({connected: true}), send: async () => false}, 'sftp-session:one', '/tmp/file'), false);
});

test('folder navigation refuses a changed or disconnected source after asynchronous mounting', async () => {
    const vm = require('node:vm');
    const fs = require('node:fs');
    const path = require('node:path');
    const navigated = [];
    let source = 'sftp-session:two';
    let connected = true;
    const sandbox = {
        document: {addEventListener() {}, getElementById: () => ({})},
        SessionManager: {getSession: () => ({connected}), switchSession() {}},
        workspaceLayoutController: {openContext: () => true},
        getSFTPFileManager: () => ({
            isEmbeddedOpen: () => false,
            getPaneSourceId: () => source,
            openEmbedded: async () => {},
            navigatePaneTo: async (...args) => navigated.push(args),
        }),
    };
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../../static/js/terminal-file-bridge.js'), 'utf8'), sandbox);
    assert.equal(await sandbox.TerminalFileBridge.openFolder('one', '/logs'), false);
    assert.equal(navigated.length, 0);
    source = 'sftp-session:one';
    assert.equal(await sandbox.TerminalFileBridge.openFolder('one', '/logs'), true);
    assert.deepEqual(navigated, [['left', '/logs']]);
    connected = false;
    assert.equal(await sandbox.TerminalFileBridge.openFolder('one', '/logs'), false);
    assert.equal(navigated.length, 1);
});

test('a delayed insertion cannot close or unlock a newly opened dialog', async () => {
    const vm = require('node:vm');
    const fs = require('node:fs');
    const path = require('node:path');
    const nodes = new Map();
    const node = id => {
        if (!nodes.has(id)) nodes.set(id, {value: '', listeners: {}, classList: {contains: () => true},
            addEventListener(name, fn) { this.listeners[name] = fn; }});
        return nodes.get(id);
    };
    let ready;
    let resolveSend;
    let closed = 0;
    let switched = 0;
    const sandbox = {
        document: {addEventListener: (_event, fn) => {ready = fn;}, getElementById: node,
            querySelectorAll: () => [], querySelector: () => node('label')},
        requestAnimationFrame: fn => fn(),
        ModalManager: {open() {}, close: () => {closed += 1;}},
        SessionManager: {getSession: id => ({connected: true, username: id, host: 'host'}), switchSession: () => {switched += 1;}},
        SSHInput: {send: () => new Promise(resolve => {resolveSend = resolve;})},
    };
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../../static/js/terminal-file-bridge.js'), 'utf8'), sandbox);
    ready();
    sandbox.TerminalFileBridge.open('one', '/first', 'insert');
    const saving = node('terminalFileForm').listeners.submit({preventDefault() {}});
    sandbox.TerminalFileBridge.open('two', '/second', 'insert');
    node('terminalFileSubmit').disabled = true;
    resolveSend(true);
    await saving;
    assert.equal(closed, 0);
    assert.equal(switched, 0);
    assert.equal(node('terminalFileSubmit').disabled, true);
    assert.equal(node('terminalFilePath').value, '/second');
});

test('paths with a backslash are not typed into a shell, because fish treats it inside single quotes', () => {
    const Bridge = require('../../static/js/terminal-file-bridge.js');
    assert.equal(Bridge.quotePath(`/tmp/x${String.fromCharCode(92)}';id;#`), null);
    assert.equal(Bridge.quotePath('/tmp/plain name'), `'/tmp/plain name'`);
});
