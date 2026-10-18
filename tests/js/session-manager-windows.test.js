const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function memoryStorage() {
    const stored = new Map();
    return {
        getItem: key => (stored.has(key) ? stored.get(key) : null),
        setItem: (key, value) => stored.set(String(key), String(value)),
        removeItem: key => stored.delete(String(key)),
    };
}

function loadSessionManager({compact = false} = {}) {
    const source = fs.readFileSync(
        path.join(__dirname, '..', '..', 'static', 'js', 'session-manager.js'),
        'utf8',
    );
    const classes = new Set();
    const body = {
        dataset: {connectionHistoryScope: 'account-scope'},
        classList: {
            toggle(name, force) {
                if (force) classes.add(name);
                else classes.delete(name);
            },
            contains: name => classes.has(name),
        },
    };
    const grid = {id: 'terminalGrid'};
    const localStorage = memoryStorage();
    const sessionStorage = memoryStorage();
    const context = {
        console,
        localStorage,
        TerminalWindows: {},
        TerminalManager: {},
        CustomEvent: class CustomEvent {
            constructor(type, options) {
                this.type = type;
                this.detail = options?.detail;
            }
        },
        document: {
            body,
            getElementById: id => (id === 'terminalGrid' ? grid : null),
            querySelectorAll: () => [],
        },
        window: {
            sessionStorage,
            dispatchEvent: () => true,
            addEventListener() {},
            matchMedia: () => ({matches: compact, addEventListener() {}}),
        },
    };
    context.window.CustomEvent = context.CustomEvent;
    vm.createContext(context);
    vm.runInContext(`${source}\n;globalThis.__SessionManager = SessionManager;`, context);
    return {manager: context.__SessionManager, localStorage, sessionStorage, body};
}

// A desktop double that records what the session manager asks of it.
function stubDesktop() {
    const windows = new Map();
    let order = [];
    const desktop = {
        opened: [],
        closed: [],
        open(index, config = {}) {
            desktop.opened.push(index);
            windows.set(index, {minimized: Boolean(config.minimized)});
            if (!order.includes(index)) order.push(index);
        },
        close(index) {
            desktop.closed.push(index);
            windows.delete(index);
            order = order.filter(item => item !== index);
        },
        focus(index) {
            order = order.filter(item => item !== index).concat(index);
        },
        isOpen: index => windows.has(index),
        isMinimized: index => Boolean(windows.get(index)?.minimized),
        minimize(index) {
            windows.get(index).minimized = true;
            return true;
        },
        restore(index) {
            windows.get(index).minimized = false;
            return true;
        },
        visibleOrder: () => order.filter(index => !windows.get(index).minimized),
        order: () => order.slice(),
        topMost() {
            const visible = desktop.visibleOrder();
            return visible.length ? visible[visible.length - 1] : null;
        },
        snapshot: index => ({fraction: {x: 0.1, y: 0.1, width: 0.5, height: 0.5}, z: order.indexOf(index)}),
        bounds: () => ({width: 1200, height: 800}),
    };
    return desktop;
}

function windowManager(assignments, openSlots, options) {
    const loaded = loadSessionManager(options);
    const {manager} = loaded;
    const desktop = stubDesktop();
    openSlots.forEach(index => desktop.open(index));
    desktop.opened.length = 0;
    manager.windowMode = true;
    manager.layout = 'windows';
    manager.windowDesktop = desktop;
    manager.paneAssignments = assignments.slice();
    manager.sessions = Object.fromEntries(
        assignments.filter(Boolean).map(id => [id, {id, host: `${id}.example`, username: 'ops'}]),
    );
    manager.renderPane = () => {};
    manager.updateWindowChrome = () => {};
    return {...loaded, desktop};
}

test('split layouts keep their pane choice for new sessions', () => {
    const {manager} = loadSessionManager();
    manager.paneAssignments = ['a', null];
    manager.activePaneIndex = 0;
    assert.equal(manager.resolvePaneForNewSession(0), 0);
    assert.equal(manager.resolvePaneForNewSession(null), 1);
    manager.paneAssignments = ['a', 'b'];
    assert.equal(manager.resolvePaneForNewSession(undefined), 0);
});

test('a new session fills the empty window it was started from', () => {
    const {manager, desktop} = windowManager(['a', null, 'c'], [0, 1, 2]);
    manager.activePaneIndex = 0;
    assert.equal(manager.resolvePaneForNewSession(1), 1);
    assert.deepEqual(desktop.opened, []);
});

test('a new session never replaces the session in the focused window', () => {
    const {manager, desktop} = windowManager(['a', 'b'], [0, 1]);
    manager.activePaneIndex = 1;
    const index = manager.resolvePaneForNewSession(1);
    assert.equal(index, 2);
    assert.deepEqual(manager.paneAssignments, ['a', 'b', null]);
    assert.deepEqual(desktop.opened, [2]);
});

test('an empty focused or open window is used before opening another', () => {
    const {manager, desktop} = windowManager(['a', null, 'c', null], [0, 1, 2, 3]);
    manager.activePaneIndex = 3;
    assert.equal(manager.resolvePaneForNewSession(null), 3);
    manager.activePaneIndex = 0;
    assert.equal(manager.resolvePaneForNewSession(0), 1);
    assert.deepEqual(desktop.opened, []);
});

test('closed slots are reused before the slot list grows', () => {
    const {manager, desktop} = windowManager(['a', null, 'c'], [0, 2]);
    manager.activePaneIndex = 0;
    assert.equal(manager.getFirstEmptyPaneIndex(), -1);
    assert.deepEqual(manager.getEmptyPaneIndices(), []);
    assert.equal(manager.resolvePaneForNewSession(null), 1);
    assert.deepEqual(desktop.opened, [1]);
    assert.equal(manager.paneAssignments.length, 3);
});

test('at the window limit a new session takes the focused window', () => {
    const ids = Array.from({length: 16}, (_, index) => `s${index}`);
    const {manager, desktop} = windowManager(ids, ids.map((_, index) => index));
    manager.activePaneIndex = 5;
    assert.equal(manager.resolvePaneForNewSession(null), 5);
    assert.deepEqual(desktop.opened, []);
    assert.equal(manager.allocateWindowSlot(), -1);
});

test('global connect controls only target an empty window', () => {
    const {manager} = windowManager(['a', 'b'], [0, 1]);
    manager.activePaneIndex = 0;
    assert.equal(manager.getLauncherPaneIndex(), null);
    manager.paneAssignments = ['a', null];
    assert.equal(manager.getLauncherPaneIndex(), 1);
    manager.activePaneIndex = 1;
    assert.equal(manager.getLauncherPaneIndex(), 1);
});

test('closing a window frees its slot without shifting other windows', () => {
    const {manager, desktop} = windowManager([null, 'b', null], [0, 1, 2]);
    manager.activePaneIndex = 1;
    manager.setActivePane = () => {};
    manager.updateWindowTabState = () => {};
    manager.closeWindowSlot(2);
    assert.deepEqual(manager.paneAssignments, [null, 'b']);
    manager.closeWindowSlot(0);
    assert.deepEqual(manager.paneAssignments, [null, 'b']);
    assert.deepEqual(desktop.closed, [2, 0]);
    assert.equal(desktop.isOpen(1), true);
});

test('leaving windows hands split panes the front-most sessions first', () => {
    const {manager, desktop} = windowManager(['a', 'b', 'c', 'd'], [0, 1, 2, 3]);
    desktop.focus(2);
    desktop.focus(0);
    desktop.minimize(3);
    assert.deepEqual(Array.from(manager.getWindowStackOrder()), ['a', 'c', 'b', 'd']);
});

test('choosing a split layout turns the window preference off', () => {
    const {manager, localStorage} = windowManager(['a'], [0]);
    const calls = [];
    manager.leaveWindowMode = layout => {
        calls.push(['leave', layout]);
        manager.windowMode = false;
    };
    manager.setSplitLayout(2);
    assert.deepEqual(calls, [['leave', 2]]);
    assert.equal(localStorage.getItem('webssh.workspace.windowMode'), 'off');
    assert.equal(manager.windowModePreferred, false);
});

test('choosing windows persists the preference and enters window mode', () => {
    const {manager, localStorage} = loadSessionManager();
    let entered = 0;
    manager.enterWindowMode = () => {
        entered += 1;
        manager.windowMode = true;
    };
    manager.updateSplitControls = () => {};
    manager.setSplitLayout('windows');
    assert.equal(entered, 1);
    assert.equal(localStorage.getItem('webssh.workspace.windowMode'), 'on');
});

test('narrow screens fall back to one pane but remember the preference', () => {
    const {manager, localStorage} = loadSessionManager({compact: true});
    localStorage.setItem('webssh.workspace.windowMode', 'on');
    let entered = 0;
    manager.enterWindowMode = () => { entered += 1; };
    manager.updateSplitControls = () => {};
    manager.initWindowMode();
    assert.equal(manager.windowModePreferred, true);
    assert.equal(entered, 0);
    assert.equal(manager.windowMode, false);
});

test('window placement is stored per session in session storage', () => {
    const {manager, sessionStorage} = windowManager(['a', null, 'c'], [0, 1, 2]);
    manager.saveWindowLayouts();
    const stored = JSON.parse(sessionStorage.getItem('webssh.workspace.windows:account-scope'));
    assert.deepEqual(Object.keys(stored).sort(), ['a', 'c']);
    manager.forgetWindowLayout('a');
    assert.deepEqual(
        Object.keys(JSON.parse(sessionStorage.getItem('webssh.workspace.windows:account-scope'))),
        ['c'],
    );
});

test('a connection finishing after leaving windows uses a surviving split pane', () => {
    const {manager} = loadSessionManager();
    manager.paneAssignments = ['active'];
    manager.activePaneIndex = 0;
    assert.equal(manager.resolvePaneForNewSession(9), 0);
    assert.equal(manager.resolvePaneForNewSession(-1), 0);
    manager.paneAssignments = ['active', null];
    assert.equal(manager.resolvePaneForNewSession(9), 1);
});
