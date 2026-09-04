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

test('session pane activation delegates forced PTY synchronization to TerminalManager', () => {
    const source = fs.readFileSync(
        path.join(__dirname, '../../static/js/session-manager.js'),
        'utf8',
    );
    const setActivePane = source.slice(
        source.indexOf('    setActivePane(paneIndex) {'),
        source.indexOf('    focusActivePane() {'),
    );

    assert.match(setActivePane, /fitAndSyncVisibleTerminals/);
    assert.match(setActivePane, /force:\s*true/);
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
