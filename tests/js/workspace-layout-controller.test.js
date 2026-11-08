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
    const styleValues = new Map();
    return {
        id,
        hidden: false,
        disabled: false,
        classList: classList(),
        style: {
            setProperty(name, value) { styleValues.set(name, String(value)); },
            getPropertyValue(name) { return styleValues.get(name) || ''; },
        },
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
        'contextWorkspaceResizer',
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

test('a user-collapsed tool stays closed when its availability returns', () => {
    const {controller} = createHarness(1600);
    controller.init();
    controller.setContextAvailability('files', true);
    controller.openContext('files', 'user');
    controller.closeContext('user');
    controller.setContextAvailability('files', false);
    controller.setContextAvailability('files', true);
    assert.equal(controller.getState().activeContext, null);
    assert.equal(controller.openContext('files', 'user'), true);
    assert.equal(controller.getState().activeContext, 'files');
});

test('breakpointForWidth uses the approved desktop tablet and mobile boundaries', () => {
    const { breakpointForWidth } = require('../../static/js/workspace-layout-controller.js');

    assert.equal(breakpointForWidth(1024), 'desktop');
    assert.equal(breakpointForWidth(768), 'tablet');
    assert.equal(breakpointForWidth(767), 'mobile');
});

test('automatic context width stays bounded on wide displays', () => {
    const { defaultContextWidth } = require('../../static/js/workspace-layout-controller.js');

    assert.equal(defaultContextWidth(1280), 340);
    assert.equal(defaultContextWidth(1536), 340);
    assert.equal(defaultContextWidth(1920), 340);
    assert.equal(defaultContextWidth(3440), 340);
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
    assert.equal(state.elements.contextWorkspace.hidden, false);
    assert.equal(state.elements.contextWorkspace.getAttribute('aria-hidden'), 'false');
    assert.equal(state.elements.contextWorkspaceLauncher.hidden, true);
    assert.equal(state.documentRef.activeElement, state.elements.contextCommandsTab);
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

test('a new session selects Files only after SFTP is confirmed available', () => {
    const { controller } = createHarness(1280);
    controller.init();
    controller.setContextAvailability('files', true);
    controller.setContextAvailability('diagnostics', true);

    assert.equal(controller.selectSessionDefault({
        sessionId: 'session-a',
        sftpAvailable: null,
    }), false);
    assert.equal(controller.selectSessionDefault({
        sessionId: 'session-a',
        sftpAvailable: true,
    }), true);
    assert.equal(controller.getState().activeContext, 'files');
});

test('a new session selects Diagnostics when SFTP is unavailable', () => {
    const { controller } = createHarness(1280);
    controller.init();
    controller.setContextAvailability('diagnostics', true);

    controller.selectSessionDefault({ sessionId: 'session-a', sftpAvailable: null });
    assert.equal(controller.selectSessionDefault({
        sessionId: 'session-a',
        sftpAvailable: false,
    }), true);
    assert.equal(controller.getState().activeContext, 'diagnostics');
});

test('a context chosen while SFTP is probing is never overwritten', () => {
    const { controller } = createHarness(1280);
    controller.init();
    controller.setContextAvailability('files', true);
    controller.setContextAvailability('diagnostics', true);

    controller.selectSessionDefault({ sessionId: 'session-a', sftpAvailable: null });
    controller.openContext('notes', 'user');

    assert.equal(controller.selectSessionDefault({
        sessionId: 'session-a',
        sftpAvailable: true,
    }), false);
    assert.equal(controller.getState().activeContext, 'notes');
});

test('desktop context width restores safely and keyboard resizing persists it', () => {
    const { controller, state } = createHarness(1280);
    state.storage.setItem('webssh.workspace.contextWidth', '900');

    controller.init();

    assert.equal(controller.getContextWidth(), 720);
    assert.equal(
        state.elements.workspace.style.getPropertyValue('--context-workspace-width'),
        '720px',
    );
    assert.equal(state.elements.contextWorkspaceResizer.hidden, false);
    assert.equal(
        state.elements.contextWorkspaceResizer.getAttribute('aria-valuenow'),
        '720',
    );

    state.elements.contextWorkspaceResizer.dispatch('keydown', {
        key: 'ArrowRight',
        preventDefault() {},
    });

    assert.equal(controller.getContextWidth(), 696);
    assert.equal(state.storage.getItem('webssh.workspace.contextWidth'), '696');
    assert.equal(state.storage.getItem('webssh.workspace.contextWidthMode'), 'manual');
    assert.equal(controller.getContextWidthMode(), 'manual');
});

test('desktop context width uses automatic sizing without stored state', () => {
    const { controller, state } = createHarness(1920);

    controller.init();

    assert.equal(controller.getContextWidth(), 340);
    assert.equal(controller.getContextWidthMode(), 'auto');
    assert.equal(
        state.elements.workspace.style.getPropertyValue('--context-workspace-width'),
        '340px',
    );
});

test('legacy default width migrates to auto while custom widths stay manual', () => {
    const legacyDefault = createHarness(1920);
    legacyDefault.state.storage.setItem('webssh.workspace.contextWidth', '420');
    legacyDefault.controller.init();

    assert.equal(legacyDefault.controller.getContextWidth(), 340);
    assert.equal(legacyDefault.controller.getContextWidthMode(), 'auto');

    const legacyCustom = createHarness(1920);
    legacyCustom.state.storage.setItem('webssh.workspace.contextWidth', '512');
    legacyCustom.controller.init();

    assert.equal(legacyCustom.controller.getContextWidth(), 512);
    assert.equal(legacyCustom.controller.getContextWidthMode(), 'manual');
});

test('automatic width follows resize and double click resets manual width to auto', () => {
    const { controller, state, syncCalls } = createHarness(1280);
    controller.init();
    assert.equal(controller.getContextWidth(), 340);

    state.setWidth(1920);
    state.listeners.get('resize')?.();
    assert.equal(controller.getContextWidth(), 340);
    assert.ok(syncCalls.length > 0);

    state.elements.contextWorkspaceResizer.dispatch('keydown', {
        key: 'ArrowRight',
        preventDefault() {},
    });
    assert.equal(controller.getContextWidth(), 320);
    assert.equal(controller.getContextWidthMode(), 'manual');

    state.elements.contextWorkspaceResizer.dispatch('dblclick');
    assert.equal(controller.getContextWidth(), 340);
    assert.equal(controller.getContextWidthMode(), 'auto');
    assert.equal(state.storage.getItem('webssh.workspace.contextWidthMode'), 'auto');
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

test('entering a compact breakpoint closes session tools so the terminal stays visible', () => {
    const { controller, state, syncCalls } = createHarness();
    controller.init();
    controller.openContext('commands', 'user');
    const beforeResize = syncCalls.length;

    state.setWidth(767);
    controller.reconcile();

    assert.equal(controller.getState().mode, 'mobile');
    assert.equal(controller.getState().activeContext, null);
    assert.equal(state.elements.contextWorkspace.hidden, true);
    assert.equal(state.elements.contextWorkspaceLauncher.hidden, false);
    assert.equal(state.elements.contextWorkspaceBackdrop.classList.contains('visible'), false);
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

test('desktop vertical rail closes the active tool and remains keyboard reachable', () => {
    const { controller, state } = createHarness(1920);
    controller.init();
    controller.openContext('commands', 'user');
    assert.equal(state.elements.contextWorkspaceTabs.getAttribute('aria-orientation'), 'vertical');
    state.elements.contextCommandsTab.dispatch('click');
    assert.equal(controller.getState().activeContext, null);
    assert.equal(state.elements.contextWorkspace.hidden, false);
    assert.equal(state.elements.contextCommandsTab.getAttribute('tabindex'), '0');
    state.elements.contextWorkspaceTabs.dispatch('keydown', {
        key: 'ArrowDown', target: state.elements.contextCommandsTab, preventDefault() {},
    });
    assert.equal(controller.getState().activeContext, 'notes');
    assert.equal(state.documentRef.activeElement, state.elements.contextNotesTab);
});

test('drag resizing measures tool content separately from the fixed rail', () => {
    const { controller, state } = createHarness(1920);
    controller.init();
    state.elements.contextWorkspaceResizer.dispatch('pointerdown', {button: 0, pointerId: 1});
    state.listeners.get('document:pointermove')?.({clientX: 1408});
    state.listeners.get('document:pointerup')?.({pointerId: 1});
    assert.equal(controller.getContextWidth(), 448);
    assert.equal(state.storage.getItem('webssh.workspace.contextWidth'), '448');
    assert.equal(controller.getContextWidthMode(), 'manual');
});

test('shrinking the tool panel returns its focused editor to the visible launcher', () => {
    const {controller,state} = createHarness(1280);
    controller.init(); controller.openContext('notes','user');
    const editor = {id:'notes-editor'};
    state.elements.contextWorkspace.contains = target => target === editor;
    state.documentRef.activeElement = editor;
    state.setWidth(390); controller.reconcile();
    assert.equal(controller.getState().activeContext, null);
    assert.equal(state.documentRef.activeElement, state.elements.contextWorkspaceLauncher);
});

test('losing an active tool returns focus from its hidden panel to the replacement tab', () => {
    const {controller,state} = createHarness(1280);
    controller.init(); controller.setContextAvailability('files',true);
    controller.openContext('files','user');
    const editor = {id:'file-list'};
    state.elements.contextFilesPanel.contains = target => target === editor;
    state.documentRef.activeElement = editor;
    controller.setContextAvailability('files',false);
    const replacement = controller.getState().activeContext;
    assert.notEqual(replacement,'files');
    assert.equal(state.documentRef.activeElement, state.elements[`context${replacement[0].toUpperCase()}${replacement.slice(1)}Tab`]);
});
