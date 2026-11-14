const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function setup({terminal, clipboardText, sendText, readText} = {}) {
    let active = 'session-1';
    const session = {id: active, host: 'alpha.example', username: 'ops', connected: true};
    const context = {
        SessionManager: {getActiveSession: () => active, getSession: id => id === session.id ? session : null},
        TerminalManager: {terminals: terminal ? {'session-1': terminal} : {}},
        navigator: {clipboard: {readText: readText || (() => Promise.resolve(clipboardText))}},
        window: {socket: {connected: true}, SSHInput: {sendText}},
        document: {getElementById: () => null, addEventListener() {}},
        showNotification() {},
    };
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../../static/js/terminal-paste-guard.js'), 'utf8'), context);
    const source = fs.readFileSync(path.join(__dirname, '../../static/js/app.js'), 'utf8');
    const start = source.indexOf('    function pasteClipboardIntoActiveTerminal()');
    const end = source.indexOf('\n    function setupClipboardActions()', start);
    vm.runInNewContext(source.slice(start, end) + '\nglobalThis.paste = pasteClipboardIntoActiveTerminal;', context);
    return {paste: context.paste, guard: context.window.TerminalPasteGuard, session, setActive(value) {active = value;}};
}
const settle = () => new Promise(resolve => setImmediate(resolve));
test('clipboard button uses xterm paste for a safe active terminal', async () => {
    const pasted = [];
    const {paste} = setup({terminal: {paste: value => pasted.push(value)}, clipboardText: 'pwd',
        sendText: () => assert.fail('xterm paste must handle terminal input')});
    paste();
    await settle();
    assert.deepEqual(pasted, ['pwd']);
});
test('clipboard button uses text transport when a terminal is unavailable', async () => {
    const sent = [];
    const {paste} = setup({clipboardText: 'pwd', sendText: (id, value) => sent.push([id, value])});
    paste();
    await settle();
    assert.deepEqual(sent, [['session-1', 'pwd']]);
});
test('clipboard read started in a session never follows a later focus change', async () => {
    let resolve;
    const sent = [];
    const api = setup({readText: () => new Promise(done => {resolve = done;}), sendText: (...args) => sent.push(args)});
    api.paste();
    api.setActive('session-2');
    api.guard.onWorkspaceChange();
    api.setActive('session-1');
    resolve('pwd');
    await settle();
    assert.deepEqual(sent, []);
});
test('clipboard read cannot outlive disconnect and reconnect of the same session', async () => {
    let resolve;
    const sent = [];
    const api = setup({readText: () => new Promise(done => {resolve = done;}), sendText: (...args) => sent.push(args)});
    api.paste();
    api.session.inputGeneration = 1;
    resolve('pwd');
    await settle();
    assert.deepEqual(sent, []);
});
test('controls require preview and are rendered visibly while safe Unicode remains intact', () => {
    const {guard} = setup();
    for (const value of ['one\ntwo', 'one\r', '\x00', '\x1b[201~', '\t', '\u009b', '\u202e', '\u200f', '\u061c']) assert.equal(guard.needsReview(value), true);
    assert.equal(guard.needsReview('echo 漢字 😀'), false);
    assert.equal(guard.visibleText('<b>\t\x1b\x00\n'), '<b>[TAB][ESC][U+0000][LF]\n');
    assert.equal(guard.trimTrailingNewlines('a\nb\r\n'), 'a\nb');
});
