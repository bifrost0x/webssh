const test = require('node:test');
const assert = require('node:assert/strict');

global.window = {
    addEventListener() {},
    visualViewport: null,
};
global.document = {};
global.navigator = {};

require('../../static/js/terminal-manager.js');
const TerminalManager = global.window.TerminalManager;

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
