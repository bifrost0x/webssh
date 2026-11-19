const test = require('node:test');
const assert = require('node:assert/strict');
const {Terminal} = require('../../static/vendor/xterm/xterm.js');

global.window = {addEventListener() {}, visualViewport: null};
global.document = {};
global.navigator = {};
require('../../static/js/terminal-manager.js');
const manager = window.TerminalManager;

function contextMenu({shiftKey = false} = {}) {
    return {shiftKey, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }};
}

async function terminalWithMouse(mode) {
    const terminal = new Terminal({cols: 80, rows: 24, allowProposedApi: true});
    // 1000 reports clicks, 1003 any motion; the application turns them on.
    if (mode) await new Promise(resolve => terminal.write(`\x1b[?${mode}h`, resolve));
    return terminal;
}

test('a Herdr session hands the right click to Herdr while it tracks the mouse', async () => {
    for (const mode of [1000, 1002, 1003]) {
        const terminal = await terminalWithMouse(mode);
        assert.notEqual(terminal.modes.mouseTrackingMode, 'none');
        const event = contextMenu();
        assert.equal(manager.handleHerdrContextMenu(event, terminal, true), true);
        assert.equal(event.defaultPrevented, true);
    }
});

test('shift with right click keeps the browser menu in a Herdr session', async () => {
    const terminal = await terminalWithMouse(1000);
    const event = contextMenu({shiftKey: true});
    assert.equal(manager.handleHerdrContextMenu(event, terminal, true), false);
    assert.equal(event.defaultPrevented, false);
});

test('the browser menu stays when Herdr does not track the mouse', async () => {
    const terminal = await terminalWithMouse(null);
    assert.equal(terminal.modes.mouseTrackingMode, 'none');
    const event = contextMenu();
    assert.equal(manager.handleHerdrContextMenu(event, terminal, true), false);
    assert.equal(event.defaultPrevented, false);
});

test('tmux and standard sessions keep the browser menu', async () => {
    const terminal = await terminalWithMouse(1000);
    for (const herdr of [false, undefined, 'true', 1]) {
        const event = contextMenu();
        assert.equal(manager.handleHerdrContextMenu(event, terminal, herdr), false);
        assert.equal(event.defaultPrevented, false);
    }
});

test('the Herdr flag follows the session and is dropped with its terminal', () => {
    for (const key of ['terminals', 'sessionTerminals', 'fitAddons', 'searchAddons',
        'directorySyncDisposers', 'osc52ClipboardAllowed', 'herdrMouseMenus']) manager[key] = {};
    global.Terminal = Terminal;
    global.FitAddon = {FitAddon: class { activate() {} dispose() {} fit() {} }};
    window.SessionDirectorySync = null;
    window.TerminalAppearance = null;
    const stubs = {
        getResponsiveFontSize: () => 14, getMonoFont: () => 'monospace', buildTheme: () => ({}),
        getScrollbackLines: () => 1000, getAppearance: () => ({options: {}}),
    };
    const saved = Object.fromEntries(Object.keys(stubs).map(name => [name, manager[name]]));
    Object.assign(manager, stubs);
    try {
        manager.createTerminal('herdr-session', null, {herdrMouseMenu: true});
        manager.createTerminal('tmux-session', null, {herdrMouseMenu: 'yes'});
        manager.createTerminal('plain-session');
        assert.deepEqual(manager.herdrMouseMenus, {
            'herdr-session': true, 'tmux-session': false, 'plain-session': false,
        });
        manager.destroyTerminalKey('herdr-session', 'herdr-session');
        assert.equal('herdr-session' in manager.herdrMouseMenus, false);
    } finally {
        Object.assign(manager, saved);
        delete global.Terminal;
        delete global.FitAddon;
    }
});
