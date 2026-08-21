const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

function classList() {
    const values = new Set();
    return {
        add(...names) { names.forEach(name => values.add(name)); },
        remove(...names) { names.forEach(name => values.delete(name)); },
        toggle(name, force) {
            const enabled = force === undefined ? !values.has(name) : Boolean(force);
            if (enabled) values.add(name);
            else values.delete(name);
            return enabled;
        },
        contains(name) { return values.has(name); },
    };
}

function element(id, documentRef) {
    const attributes = new Map();
    const listeners = new Map();
    return {
        id,
        hidden: false,
        disabled: false,
        classList: classList(),
        addEventListener(name, listener) { listeners.set(name, listener); },
        removeEventListener(name) { listeners.delete(name); },
        dispatch(name, event = {}) { listeners.get(name)?.({ currentTarget: this, ...event }); },
        setAttribute(name, value) { attributes.set(name, String(value)); },
        removeAttribute(name) { attributes.delete(name); },
        getAttribute(name) { return attributes.get(name) ?? null; },
        focus() { documentRef.activeElement = this; },
    };
}

function fixture(width = 1280) {
    const listeners = new Map();
    const events = [];
    const mediaQueries = [];
    const documentRef = {
        activeElement: null,
        getElementById(id) { return elements[id] || null; },
        addEventListener(name, listener) { listeners.set(`document:${name}`, listener); },
        removeEventListener(name) { listeners.delete(`document:${name}`); },
        dispatchEvent(event) { events.push({ type: event.type, detail: event.detail }); },
        contains(target) { return Object.values(elements).includes(target); },
    };
    const ids = [
        'workspace',
        'contextWorkspace',
        'contextWorkspaceLauncher',
        'contextWorkspaceClose',
        'contextWorkspaceBackdrop',
        'contextWorkspaceTabs',
        'contextFilesTab',
        'contextCommandsTab',
        'contextDiagnosticsTab',
        'contextNotesTab',
        'contextFilesPanel',
        'contextCommandsPanel',
        'contextDiagnosticsPanel',
        'contextNotesPanel',
        'mobileMenuBtn',
        'headerButtons',
    ];
    const elements = Object.fromEntries(ids.map(id => [id, element(id, documentRef)]));
    const contextTabs = [
        elements.contextFilesTab,
        elements.contextCommandsTab,
        elements.contextDiagnosticsTab,
        elements.contextNotesTab,
    ];
    ['files', 'commands', 'diagnostics', 'notes'].forEach((name, index) => {
        contextTabs[index].setAttribute('data-workspace-context', name);
    });
    elements.contextWorkspaceTabs.querySelectorAll = selector => (
        selector === '[data-workspace-context]' ? contextTabs : []
    );
    const windowRef = {
        innerWidth: width,
        visualViewport: null,
        CustomEvent: class CustomEvent {
            constructor(type, options = {}) { this.type = type; this.detail = options.detail; }
        },
        addEventListener(name, listener) { listeners.set(name, listener); },
        removeEventListener(name) { listeners.delete(name); },
        matchMedia(query) {
            const entry = {
                media: query,
                matches: false,
                addEventListener() {},
                removeEventListener() {},
            };
            mediaQueries.push(entry);
            return entry;
        },
        setTimeout(callback) { callback(); return 1; },
        clearTimeout() {},
    };
    const storage = {
        values: new Map(),
        getItem(key) { return this.values.get(key) ?? null; },
        setItem(key, value) { this.values.set(key, String(value)); },
    };
    return {
        elements,
        listeners,
        mediaQueries,
        windowRef,
        documentRef,
        storage,
        events,
        setWidth(nextWidth) { windowRef.innerWidth = nextWidth; },
    };
}

function createHarness(width = 1280) {
    const { createController } = require('../../static/js/workspace-layout-controller.js');
    const state = fixture(width);
    const syncCalls = [];
    const controller = createController({
        window: state.windowRef,
        document: state.documentRef,
        storage: state.storage,
        terminalManager: {
            fitAndSyncVisibleTerminals(options) { syncCalls.push(options); },
        },
        sessionManager: { getSession() { return null; } },
        socket: { emit() {} },
    });
    return { controller, state, syncCalls };
}

test('breakpointForWidth uses the approved desktop tablet and mobile boundaries', () => {
    const { breakpointForWidth } = require('../../static/js/workspace-layout-controller.js');

    assert.equal(breakpointForWidth(1024), 'desktop');
    assert.equal(breakpointForWidth(768), 'tablet');
    assert.equal(breakpointForWidth(767), 'mobile');
});

test('desktop starts with the last available context open and still allows dismissal', () => {
    const { controller, state } = createHarness(1280);
    state.storage.setItem('webssh.workspace.lastContext', 'commands');

    controller.init();

    assert.equal(controller.getState().activeContext, 'commands');
    assert.equal(state.elements.contextWorkspace.hidden, false);
    assert.equal(state.elements.contextWorkspaceLauncher.hidden, true);

    state.elements.contextWorkspaceClose.dispatch('click');

    assert.equal(controller.getState().activeContext, null);
    assert.equal(state.elements.contextWorkspace.hidden, true);
    assert.equal(state.elements.contextWorkspaceLauncher.hidden, false);
});

test('mobile starts with the context workspace closed to keep the terminal reachable', () => {
    const { controller, state } = createHarness(360);
    state.storage.setItem('webssh.workspace.lastContext', 'commands');

    controller.init();

    assert.equal(controller.getState().activeContext, null);
    assert.equal(state.elements.contextWorkspace.hidden, true);
    assert.equal(state.elements.contextWorkspaceLauncher.hidden, false);
});

test('desktop promotes Files when the first SFTP-capable session becomes available', () => {
    const { controller, state } = createHarness(1280);

    controller.init();
    assert.equal(controller.getState().activeContext, 'notes');

    controller.setContextAvailability('files', true);

    assert.equal(controller.getState().activeContext, 'files');
    assert.equal(state.elements.contextFilesPanel.hidden, false);
    assert.equal(state.elements.contextNotesPanel.hidden, true);
});

test('mobile keeps the context workspace closed when SFTP becomes available', () => {
    const { controller, state } = createHarness(360);

    controller.init();
    controller.setContextAvailability('files', true);

    assert.equal(controller.getState().activeContext, null);
    assert.equal(state.elements.contextWorkspace.hidden, true);
});

test('one persisted context owns all four panels exclusively', () => {
    const { controller, state } = createHarness();
    controller.init();
    controller.setContextAvailability('files', true);
    controller.setContextAvailability('diagnostics', true);

    assert.equal(controller.openContext('files', 'user'), true);
    assert.equal(controller.getState().activeContext, 'files');
    assert.equal(state.elements.contextFilesPanel.hidden, false);
    assert.equal(state.elements.contextCommandsPanel.hidden, true);

    assert.equal(controller.openContext('notes', 'user'), true);
    assert.deepEqual(controller.getState(), {
        mode: 'desktop',
        activeContext: 'notes',
        lastContext: 'notes',
    });
    assert.equal(state.storage.getItem('webssh.workspace.lastContext'), 'notes');
    assert.equal(state.elements.contextFilesPanel.hidden, true);
    assert.equal(state.elements.contextNotesPanel.hidden, false);
    assert.equal(state.elements.contextFilesTab.getAttribute('aria-selected'), 'false');
    assert.equal(state.elements.contextNotesTab.getAttribute('aria-selected'), 'true');
    assert.equal(state.elements.workspace.classList.contains('context-open'), true);
});

test('disabled session contexts cannot open and fall back safely when active', () => {
    const { controller, state } = createHarness();
    controller.init();

    assert.equal(controller.openContext('files', 'user'), false);
    assert.equal(state.elements.contextFilesTab.disabled, true);
    assert.equal(state.elements.contextFilesTab.getAttribute('aria-disabled'), 'true');

    controller.setContextAvailability('files', true);
    controller.openContext('files', 'user');
    controller.setContextAvailability('files', false);
    assert.equal(controller.getState().activeContext, 'notes');
    assert.equal(state.elements.contextNotesPanel.hidden, false);
});

test('context remains open across breakpoints and every layout change syncs PTY size', () => {
    const { controller, state, syncCalls } = createHarness();
    controller.init();
    controller.openContext('commands', 'user');
    const beforeResize = syncCalls.length;

    state.setWidth(767);
    controller.reconcile();

    assert.equal(controller.getState().mode, 'mobile');
    assert.equal(controller.getState().activeContext, 'commands');
    assert.equal(state.elements.contextWorkspaceBackdrop.classList.contains('visible'), true);
    assert.ok(syncCalls.length > beforeResize);
    assert.equal(syncCalls.at(-1).force, true);
});

test('tab keyboard navigation skips disabled contexts and Escape closes mobile panel', () => {
    const { controller, state } = createHarness(360);
    controller.init();
    controller.setContextAvailability('diagnostics', true);
    controller.openContext('commands', 'user');
    state.elements.contextCommandsTab.focus();

    state.elements.contextWorkspaceTabs.dispatch('keydown', {
        key: 'ArrowRight',
        preventDefault() {},
        target: state.elements.contextCommandsTab,
    });
    assert.equal(controller.getState().activeContext, 'diagnostics');
    assert.equal(state.documentRef.activeElement, state.elements.contextDiagnosticsTab);

    state.listeners.get('document:keydown')?.({ key: 'Escape', preventDefault() {} });
    assert.equal(controller.getState().activeContext, null);
    assert.equal(state.documentRef.activeElement, state.elements.contextWorkspaceLauncher);
});

test('app startup uses the layout controller instead of the legacy resize handle', () => {
    const source = fs.readFileSync(
        path.join(__dirname, '../../static/js/app.js'),
        'utf8',
    );

    assert.match(source, /WorkspaceLayoutController\?\.createController/);
    assert.doesNotMatch(source, /setupResizeHandle\(\)/);
    assert.doesNotMatch(source, /workspace-notepad-width/);
    assert.doesNotMatch(source, /notepadCollapsed/);
});
