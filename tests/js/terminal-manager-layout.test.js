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

test('new terminals use 500 scrollback lines when no preference is stored', () => {
    const source = fs.readFileSync(
        path.join(__dirname, '../../static/js/terminal-manager.js'),
        'utf8',
    );

    assert.match(
        source,
        /localStorage\.getItem\('terminalScrollback'\) \|\| '500'/,
    );
});

test('virtual keyboard detection follows visual viewport occlusion, not browser resize history', () => {
    assert.equal(TerminalManager.isVirtualKeyboardVisible(640, 640), false);
    assert.equal(TerminalManager.isVirtualKeyboardVisible(420, 640), true);
    assert.equal(TerminalManager.isVirtualKeyboardVisible(0, 640), false);
});

test('touch dragging the terminal is bridged into cancelable wheel input', () => {
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

    const dispose = TerminalManager.setupTouchScroll(surface, {element: surface});
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
    const originalConsoleError = console.error;
    const writes = [];
    const terminal = {
        buffer: { active: { viewportY: 0, baseY: 0 } },
        open() {},
        clear() {},
        write(data, callback) {
            writes.push(data);
            callback?.();
        },
        scrollToBottom() {},
    };

    try {
        TerminalManager.terminals = {};
        TerminalManager.sessionTerminals = {};
        TerminalManager.pendingOutput = {};
        TerminalManager.terminalReady = {};
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

        assert.equal(
            TerminalManager.attachTerminal('switch-session', 'terminal-container', 'switchTerminal'),
            true
        );
        TerminalManager.writeOutputToTerminal('switchTerminal', ' ready');

        await new Promise(resolve => setTimeout(resolve, 80));

        assert.deepEqual(writes, ['Switch#', ' ready']);
    } finally {
        global.document.getElementById = originalGetElementById;
        global.requestAnimationFrame = originalRequestAnimationFrame;
        TerminalManager.setupScrollbar = originalSetupScrollbar;
        TerminalManager.fitTerminal = originalFitTerminal;
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
});
