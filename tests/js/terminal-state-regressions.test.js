const test = require('node:test');
const assert = require('node:assert/strict');
const {Terminal} = require('../../static/vendor/xterm/xterm.js');

global.window = {addEventListener() {}, visualViewport: null};
global.document = {};
global.navigator = {};
require('../../static/js/terminal-manager.js');
const manager = window.TerminalManager;

function setup() {
    for (const key of ['terminals', 'sessionTerminals', 'terminalReady',
        'pendingOutput', 'pendingOutputSizes', 'transcripts', 'transcriptSizes',
        'sequencedOutput', 'sequencedOutputSizes', 'lastOutputSequences',
        'backgroundWrites', 'terminalWriteCallbacks',
        'clipboardDisposers', 'osc52ClipboardAllowed']) manager[key] = {};
    let hidden = false;
    const terminal = new Terminal({cols: 80, rows: 24, allowProposedApi: true});
    Object.defineProperty(terminal, 'element', {
        value: {closest: () => ({classList: {contains: () => hidden}})},
    });
    manager.terminals.k = terminal;
    manager.sessionTerminals.s = ['k'];
    manager.terminalReady.k = true;
    return {terminal, hide(value) { hidden = value; }};
}

const accept = data => new Promise(resolve => manager.writeOutput('s', data, null, resolve));
const resume = () => manager.resumeVisibleOutput('s');
const drained = terminal => new Promise(resolve => terminal.write('', resolve));

function showRestored(peer) {
    peer.hide(false);
    if (manager.consumeDeferredReplay?.('s')) manager.replayDeferredOutput('s');
    else manager.resumeVisibleOutput('s');
}

async function flushParser(terminal) {
    await drained(terminal);
    manager.flushBackgroundOutput('k');
    await drained(terminal);
}

test('showing a restored hidden terminal acknowledges its queued live batch once', async () => {
    const peer = setup();
    try {
        peer.hide(true);
        manager.resyncRestoredOutput('s', 'snapshot', 0);
        await flushParser(peer.terminal);
        let acknowledgements = 0;
        manager.writeOutput('s', '-live', 1, () => acknowledgements++);
        showRestored(peer);
        await flushParser(peer.terminal);
        assert.equal(peer.terminal.buffer.active.getLine(0).translateToString(true), 'snapshot-live');
        assert.equal(acknowledgements, 1);
        assert.equal(manager.terminalWriteCallbacks.k.size, 0);
    } finally {
        manager.destroyTerminal('s');
    }
});

test('live output arriving as a restored terminal becomes visible is parsed and acknowledged', async () => {
    const peer = setup();
    try {
        peer.hide(true);
        manager.resyncRestoredOutput('s', 'snapshot', 0);
        showRestored(peer);
        let acknowledgements = 0;
        manager.writeOutput('s', '-new', 1, () => acknowledgements++);
        await flushParser(peer.terminal);
        assert.equal(peer.terminal.buffer.active.getLine(0).translateToString(true), 'snapshot-new');
        assert.equal(acknowledgements, 1);
        assert.equal((manager.pendingOutput.k || []).length, 0);
    } finally {
        manager.destroyTerminal('s');
    }
});

test('restored hidden terminal preserves protocol modes after transcript eviction', async () => {
    const peer = setup();
    try {
        const modes = '\x1b[?1049h\x1b[?2004h\x1b[?1h';
        await accept(modes);
        peer.hide(true);
        manager.resyncRestoredOutput('s', modes, 0);
        await flushParser(peer.terminal);
        await accept('x'.repeat(110000));
        await accept('y'.repeat(110000));
        assert.equal(manager.getTranscript('s').includes(modes), false);
        showRestored(peer);
        await flushParser(peer.terminal);
        assert.equal(peer.terminal.buffer.active.type, 'alternate');
        assert.equal(peer.terminal.modes.bracketedPasteMode, true);
        assert.equal(peer.terminal.modes.applicationCursorKeysMode, true);
    } finally {
        manager.destroyTerminal('s');
    }
});

test('terminal resync brackets restored output as unsafe directory-sync history', async () => {
    const peer = setup();
    const calls = [];
    window.SessionDirectorySync = {
        beginReplay(sessionId) { calls.push(['begin', sessionId]); },
        endReplay(sessionId) { calls.push(['end', sessionId]); },
    };
    try {
        manager.resyncRestoredOutput('s', '\x1b[?2004hpartial input', 0);
        assert.deepEqual(calls, [['begin', 's']]);
        await flushParser(peer.terminal);
        assert.deepEqual(calls, [['begin', 's'], ['end', 's']]);
    } finally {
        delete window.SessionDirectorySync;
        manager.destroyTerminal('s');
    }
});

test('background transcript eviction preserves terminal protocol modes', async () => {
    const peer = setup();
    try {
        await accept('\x1b[?1049h\x1b[?2004h\x1b[?1h');
        peer.hide(true);
        await accept('x'.repeat(110000));
        await accept('y'.repeat(110000));
        peer.hide(false);
        resume();
        await drained(peer.terminal);
        assert.equal(peer.terminal.buffer.active.type, 'alternate');
        assert.equal(peer.terminal.modes.bracketedPasteMode, true);
        assert.equal(peer.terminal.modes.applicationCursorKeysMode, true);
    } finally {
        manager.destroyTerminalKey('k', 's');
    }
});

test('switching with an in-flight write does not duplicate output', async () => {
    const peer = setup();
    try {
        manager.writeOutput('s', 'before ');
        peer.hide(true);
        manager.writeOutput('s', 'during');
        peer.hide(false);
        resume();
        await drained(peer.terminal);
        assert.equal(peer.terminal.buffer.active.getLine(0).translateToString(true), 'before during');
    } finally {
        manager.destroyTerminalKey('k', 's');
    }
});

test('background batching preserves escape sequences split across writes', async () => {
    const peer = setup();
    try {
        await accept('\x1b[?20');
        peer.hide(true);
        await accept('04h');
        peer.hide(false);
        resume();
        await drained(peer.terminal);
        assert.equal(peer.terminal.modes.bracketedPasteMode, true);
    } finally {
        manager.destroyTerminalKey('k', 's');
    }
});

test('hidden resync retires old transport callbacks and rebuilds before showing', async () => {
    const peer = setup();
    try {
        peer.hide(true);
        let staleAcknowledgements = 0;
        manager.writeOutput('s', 'old', 1, () => staleAcknowledgements++);
        manager.resyncRestoredOutput('s', 'snapshot', 1);
        await drained(peer.terminal);
        manager.flushBackgroundOutput('k');
        await drained(peer.terminal);
        assert.equal(staleAcknowledgements, 0);
        assert.equal(peer.terminal.buffer.active.getLine(0).translateToString(true), 'snapshot');
        showRestored(peer);
        await drained(peer.terminal);
        assert.equal(peer.terminal.buffer.active.getLine(0).translateToString(true), 'snapshot');
    } finally {
        manager.destroyTerminalKey('k', 's');
    }
});

test('screen restoration continues to forward user input while xterm rebuilds history', async () => {
    const peer = setup();
    const sent = [];
    manager.setupInputHandler('s', data => sent.push(data));
    try {
        manager.resyncRestoredOutput('s', 'retained screen', 0);
        peer.terminal.input('echo retained\r', true);
        assert.deepEqual(sent, ['echo retained\r']);
        await flushParser(peer.terminal);
        assert.equal(peer.terminal.buffer.active.getLine(0).translateToString(true), 'retained screen');
    } finally {
        manager.destroyTerminal('s');
    }
});
