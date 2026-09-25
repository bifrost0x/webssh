const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function loadPasteAction({terminal, clipboardText, sendText}) {
    const source = fs.readFileSync(path.join(__dirname, '../../static/js/app.js'), 'utf8');
    const start = source.indexOf('    function pasteClipboardIntoActiveTerminal()');
    const end = source.indexOf('\n    function setupClipboardActions()', start);
    const context = {
        SessionManager: {getActiveSession: () => 'session-1'},
        TerminalManager: {terminals: terminal ? {'session-1': terminal} : {}},
        navigator: {clipboard: {readText: () => Promise.resolve(clipboardText)}},
        window: {socket: {connected: true}, SSHInput: {sendText}},
        showNotification() {},
    };
    vm.runInNewContext(source.slice(start, end) + '\nglobalThis.paste = pasteClipboardIntoActiveTerminal;', context);
    return context.paste;
}

test('clipboard button uses xterm paste for an active terminal', async () => {
    const pasted = [];
    const paste = loadPasteAction({
        terminal: {paste: value => pasted.push(value)},
        clipboardText: 'first\nsecond',
        sendText: () => assert.fail('xterm paste must handle terminal input'),
    });

    paste();
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(pasted, ['first\nsecond']);
});

test('clipboard button normalizes text when a terminal is unavailable', async () => {
    const sent = [];
    const paste = loadPasteAction({
        clipboardText: 'first\r\nsecond',
        sendText: (id, value) => sent.push([id, value]),
    });

    paste();
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(sent, [['session-1', 'first\r\nsecond']]);
});
