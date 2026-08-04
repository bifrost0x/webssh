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
