const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

global.window = {
    addEventListener() {},
    visualViewport: null,
};
global.document = {};
global.navigator = {};

require('../../static/js/terminal-manager.js');
const TerminalManager = global.window.TerminalManager;

function wrapperMock(unassigned) {
    let hidden = unassigned;
    return {
        setUnassigned(value) { hidden = value; },
        classList: {
            contains(name) {
                return name === 'unassigned' && hidden;
            },
        },
    };
}

function xtermMock(unassigned, hooks = {}) {
    const wrapper = wrapperMock(unassigned);
    const terminal = {
        rows: 24,
        cols: 80,
        buffer: {active: {viewportY: 0, baseY: 0, length: 100}},
        element: {
            closest: () => wrapper,
        },
        write(data, callback) {
            hooks.writes = hooks.writes || [];
            hooks.callbacks = hooks.callbacks || [];
            hooks.writes.push(data);
            hooks.callbacks.push(callback);
        },
        scrollToBottom() {
            hooks.scrolls = (hooks.scrolls || 0) + 1;
        },
        reset() {
            hooks.resets = (hooks.resets || 0) + 1;
        },
        dispose() {},
    };
    return {terminal, wrapper, hooks};
}

function resetManager() {
    TerminalManager.terminals = {};
    TerminalManager.sessionTerminals = {};
    TerminalManager.terminalReady = {};
    TerminalManager.pendingOutput = {};
    TerminalManager.pendingOutputSizes = {};
    TerminalManager.transcripts = {};
    TerminalManager.transcriptSizes = {};
    TerminalManager.sequencedOutput = {};
    TerminalManager.sequencedOutputSizes = {};
    TerminalManager.lastOutputSequences = {};
    TerminalManager.backgroundWrites = {};
    TerminalManager.terminalWriteCallbacks = {};
    TerminalManager.clipboardDisposers = {};
    TerminalManager.osc52ClipboardAllowed = {};
    TerminalManager.scrollbarDisposers = {};
}

test('hidden chunks batch parser work without scrolling and ACK after consumption', () => {
    resetManager();
    const hidden = xtermMock(true);
    TerminalManager.terminals = {k: hidden.terminal};
    TerminalManager.sessionTerminals = {s: ['k']};
    TerminalManager.terminalReady = {k: true};
    let acknowledgements = 0;
    for (let i = 1; i <= 8; i++) {
        TerminalManager.writeOutput('s', String(i), i, () => acknowledgements++);
    }
    assert.equal(acknowledgements, 0);
    assert.equal(hidden.hooks.writes, undefined);
    TerminalManager.flushBackgroundOutput('k');
    assert.deepEqual(hidden.hooks.writes, ['12345678']);
    assert.equal(acknowledgements, 0);
    hidden.hooks.callbacks[0]();
    assert.equal(acknowledgements, 8);
    assert.equal(hidden.hooks.scrolls || 0, 0);
    assert.equal(TerminalManager.getTranscript('s'), '12345678');
    assert.equal(TerminalManager.backgroundWrites.k, undefined);
});

test('visible output flushes older background bytes first without resetting', () => {
    resetManager();
    const peer = xtermMock(true);
    TerminalManager.terminals = {k: peer.terminal};
    TerminalManager.sessionTerminals = {s: ['k']};
    TerminalManager.terminalReady = {k: true};
    TerminalManager.writeOutput('s', 'background');
    peer.wrapper.setUnassigned(false);
    TerminalManager.writeOutput('s', 'live');
    assert.deepEqual(peer.hooks.writes, ['background', 'live']);
    assert.equal(peer.hooks.resets || 0, 0);
    TerminalManager.destroyTerminalKey('k', 's');
});

test('background batch flushes at its byte and event limits', () => {
    resetManager();
    const peer = xtermMock(true);
    TerminalManager.terminals = {k: peer.terminal};
    TerminalManager.sessionTerminals = {s: ['k']};
    TerminalManager.terminalReady = {k: true};
    TerminalManager.writeOutput('s', 'x'.repeat(TerminalManager.maxBackgroundWriteSize));
    assert.equal(peer.hooks.writes.length, 1);
    assert.equal(TerminalManager.backgroundWrites.k, undefined);
    for (let i = 0; i < TerminalManager.maxBackgroundWriteEvents; i++) {
        TerminalManager.writeOutput('s', 'a');
    }
    assert.equal(peer.hooks.writes.length, 2);
    assert.equal(TerminalManager.backgroundWrites.k, undefined);
    TerminalManager.destroyTerminalKey('k', 's');
});

test('destroy cancels queued background writes and releases each ACK once', async () => {
    resetManager();
    const peer = xtermMock(true);
    TerminalManager.terminals = {k: peer.terminal};
    TerminalManager.sessionTerminals = {s: ['k']};
    TerminalManager.terminalReady = {k: true};
    let acknowledgements = 0;
    TerminalManager.writeOutput('s', 'pending', null, () => acknowledgements++);
    TerminalManager.destroyTerminalKey('k', 's');
    await new Promise(resolve => setTimeout(resolve, 25));
    assert.equal(acknowledgements, 1);
    assert.equal(peer.hooks.writes, undefined);
    assert.equal(TerminalManager.backgroundWrites.k, undefined);
});

test('scrollbar interval skips DOM work for hidden panes and disposes cleanly', () => {
    resetManager();
    const originalSetInterval = global.setInterval;
    const originalClearInterval = global.clearInterval;
    const originalCreateElement = global.document.createElement;
    let intervalCallback = null;
    const cleared = [];
    const thumb = {
        style: {},
        setPointerCapture() {},
        addEventListener() {},
        removeEventListener() {},
    };
    const scrollbar = {
        className: '',
        innerHTML: '',
        style: {},
        clientHeight: 200,
        querySelector: () => thumb,
        addEventListener() {},
        removeEventListener() {},
        remove() {},
    };
    global.setInterval = callback => {
        intervalCallback = callback;
        return 999;
    };
    global.clearInterval = id => {
        cleared.push(id);
    };
    global.document.createElement = () => scrollbar;
    try {
        const peer = xtermMock(false);
        peer.terminal.buffer.active.length = 500;
        peer.terminal.onScroll = () => ({dispose() {}});
        peer.terminal.onResize = () => ({dispose() {}});
        TerminalManager.terminals = {scrollKey: peer.terminal};

        const container = {style: {}, appendChild() {}};
        TerminalManager.setupScrollbar(container, peer.terminal, 'scrollKey');
        assert.equal(typeof intervalCallback, 'function');

        const visibleTop = thumb.style.top;
        peer.terminal.buffer.active.viewportY = 40;
        intervalCallback();
        assert.notEqual(thumb.style.top, visibleTop);

        peer.wrapper.setUnassigned(true);
        const frozen = {...thumb.style};
        const frozenDisplay = scrollbar.style.display;
        peer.terminal.buffer.active.viewportY = 120;
        intervalCallback();
        assert.deepEqual({...thumb.style}, frozen);
        assert.equal(scrollbar.style.display, frozenDisplay);

        TerminalManager.scrollbarDisposers.scrollKey();
        assert.deepEqual(cleared, [999]);
        assert.equal(TerminalManager.scrollbarDisposers.scrollKey, undefined);
    } finally {
        global.setInterval = originalSetInterval;
        global.clearInterval = originalClearInterval;
        if (originalCreateElement === undefined) {
            delete global.document.createElement;
        } else {
            global.document.createElement = originalCreateElement;
        }
    }
});

test('scrollbar coalesces scroll bursts into one layout read per frame', () => {
    resetManager();
    const originals = {
        setInterval: global.setInterval,
        clearInterval: global.clearInterval,
        createElement: global.document.createElement,
        requestAnimationFrame: global.requestAnimationFrame,
        cancelAnimationFrame: global.cancelAnimationFrame,
    };
    const frames = new Map();
    let nextFrame = 1;
    const cancelled = [];
    let layoutReads = 0;
    let scrollListener = null;
    const thumb = {
        style: {},
        setPointerCapture() {},
        addEventListener() {},
        removeEventListener() {},
    };
    const scrollbar = {
        className: '',
        innerHTML: '',
        style: {},
        get clientHeight() { layoutReads += 1; return 200; },
        querySelector: () => thumb,
        addEventListener() {},
        removeEventListener() {},
        remove() {},
    };
    global.setInterval = () => 7;
    global.clearInterval = () => {};
    global.document.createElement = () => scrollbar;
    global.requestAnimationFrame = callback => {
        const id = nextFrame++;
        frames.set(id, callback);
        return id;
    };
    global.cancelAnimationFrame = id => {
        cancelled.push(id);
        frames.delete(id);
    };
    const runFrames = () => {
        const pending = [...frames.values()];
        frames.clear();
        pending.forEach(callback => callback());
    };
    try {
        const peer = xtermMock(false);
        peer.terminal.buffer.active.length = 500;
        peer.terminal.onScroll = listener => {
            scrollListener = listener;
            return {dispose() {}};
        };
        peer.terminal.onResize = () => ({dispose() {}});
        TerminalManager.terminals = {scrollKey: peer.terminal};

        TerminalManager.setupScrollbar({style: {}, appendChild() {}}, peer.terminal, 'scrollKey');
        const initialReads = layoutReads;
        const initialTop = thumb.style.top;

        for (let line = 1; line <= 50; line += 1) {
            peer.terminal.buffer.active.viewportY = line;
            scrollListener();
        }
        assert.equal(layoutReads, initialReads);
        assert.equal(frames.size, 1);

        runFrames();
        assert.equal(layoutReads, initialReads + 1);
        assert.notEqual(thumb.style.top, initialTop);
        assert.equal(thumb.style.top, `${(50 / 476) * (200 - 30)}px`);

        scrollListener();
        assert.equal(frames.size, 1);
        const pendingId = [...frames.keys()][0];
        TerminalManager.scrollbarDisposers.scrollKey();
        assert.deepEqual(cancelled, [pendingId]);
        assert.equal(frames.size, 0);
    } finally {
        global.setInterval = originals.setInterval;
        global.clearInterval = originals.clearInterval;
        global.requestAnimationFrame = originals.requestAnimationFrame;
        global.cancelAnimationFrame = originals.cancelAnimationFrame;
        if (originals.requestAnimationFrame === undefined) delete global.requestAnimationFrame;
        if (originals.cancelAnimationFrame === undefined) delete global.cancelAnimationFrame;
        if (originals.createElement === undefined) {
            delete global.document.createElement;
        } else {
            global.document.createElement = originals.createElement;
        }
    }
});

function loadSessionManager(termStub) {
    const source = fs.readFileSync(
        path.join(__dirname, '..', '..', 'static', 'js', 'session-manager.js'),
        'utf8',
    );
    const panes = new Map();
    const wrappers = new Map();
    const grid = {
        querySelector(selector) {
            const match = selector.match(/data-pane-index="(\d+)"/);
            return match ? panes.get(Number(match[1])) || null : null;
        },
    };
    const context = {
        console,
        document: {
            body: {dataset: {}},
            createElement: () => ({
                children: [],
                appendChild(child) {
                    this.children.push(child);
                    return child;
                },
            }),
            getElementById(id) {
                if (id === 'terminalGrid') return grid;
                return wrappers.get(id) || null;
            },
        },
        TerminalManager: termStub,
        CustomEvent: class CustomEvent {},
        window: {},
        localStorage: {
            getItem: () => null,
            setItem() {},
            removeItem() {},
        },
    };
    vm.createContext(context);
    vm.runInContext(
        `${source}\n;globalThis.__SessionManager = SessionManager;`,
        context,
    );
    return {manager: context.__SessionManager, panes, wrappers};
}

test('renderPane flushes queued background output when a session becomes visible', () => {
    const calls = {fit: [], replay: []};
    const {manager, panes, wrappers} = loadSessionManager({
        fitTerminal: sessionId => calls.fit.push(sessionId),
        resumeVisibleOutput: sessionId => calls.replay.push(sessionId),
    });
    const removed = [];
    const appended = [];
    wrappers.set('term-s1', {
        classList: {remove: name => removed.push(name)},
    });
    panes.set(0, {
        innerHTML: 'stale',
        appendChild: node => appended.push(node),
    });
    manager.sessions = {s1: {id: 's1', terminalId: 'term-s1'}};
    manager.paneAssignments = ['s1'];

    manager.renderPane(0);

    assert.deepEqual(removed, ['unassigned']);
    assert.deepEqual(appended, [wrappers.get('term-s1')]);
    assert.deepEqual(calls.fit, ['s1']);
    assert.deepEqual(calls.replay, ['s1']);
});
