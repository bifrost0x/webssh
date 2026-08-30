const test = require('node:test');
const assert = require('node:assert/strict');

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

function element(id = '', focusState = null) {
    const listeners = new Map();
    const attributes = new Map();
    return {
        id,
        hidden: false,
        disabled: false,
        inert: false,
        isConnected: true,
        children: [],
        dataset: {},
        classList: classList(),
        addEventListener(name, listener) { listeners.set(name, listener); },
        removeEventListener(name, listener) {
            if (listeners.get(name) === listener) listeners.delete(name);
        },
        dispatch(name, event = {}) {
            listeners.get(name)?.({currentTarget: this, preventDefault() {}, ...event});
        },
        setAttribute(name, value) { attributes.set(name, String(value)); },
        removeAttribute(name) { attributes.delete(name); },
        getAttribute(name) { return attributes.get(name) ?? null; },
        click() { this.clicks = (this.clicks || 0) + 1; },
        focus() {
            this.focused = true;
            if (focusState) focusState.activeElement = this;
        },
        scrollIntoView() { this.scrolled = true; },
        contains(target) { return this === target || this.children.includes(target); },
        querySelector() { return this.children[0] || null; },
        querySelectorAll() { return this.children; },
    };
}

function fixture() {
    const windowListeners = new Map();
    const documentListeners = new Map();
    const focusState = {activeElement: null};
    const views = ['workspaces', 'hosts', 'files', 'commands', 'more'].map(view => {
        const button = element(`dock-${view}`, focusState);
        button.dataset.mobileView = view;
        return button;
    });
    const ids = [
        'headerButtons', 'mobileMenuBtn', 'mobileMenuBackdrop', 'mobileMoreBtn',
        'mobileCommandToggle', 'mobileInputCloseBtn', 'mobileInput', 'mobileSessionSummary',
        'mobileSessionSummaryLabel', 'workspaceNavBtn', 'manageProfilesBtn',
        'fileTransferBtn', 'commandLibraryBtn', 'mobileQuickConnectAction',
        'mobileToolsAction', 'mobileBroadcastAction', 'mobileTranscriptAction',
        'accountBtnHeader',
        'newTabBtn', 'contextWorkspaceLauncher', 'broadcastToggleBtn', 'saveTranscriptBtn',
        'tab-active', 'primaryWorkspaceSurface', 'workspaceStatusBar', 'mobileAppDock',
    ];
    const elements = Object.fromEntries(ids.map(id => [id, element(id, focusState)]));
    elements.mobileMoreBtn = views.at(-1);
    elements.headerButtons.children = [
        elements.workspaceNavBtn,
        elements.fileTransferBtn,
        elements.manageProfilesBtn,
        elements.commandLibraryBtn,
        elements.mobileQuickConnectAction,
        elements.mobileToolsAction,
        elements.mobileBroadcastAction,
        elements.mobileTranscriptAction,
        elements.accountBtnHeader,
    ];
    const status = element('status', focusState);
    const body = element('body', focusState);
    const classElements = {
        '.header-title-row': element('header-title-row', focusState),
        '.session-tabs-row': element('session-tabs-row', focusState),
        '.main-content': element('main-content', focusState),
    };
    body.dataset.primaryWorkspace = 'workspaces';
    const documentRef = {
        body,
        get activeElement() { return focusState.activeElement; },
        getElementById(id) { return elements[id] || null; },
        querySelector(selector) {
            if (selector === '.mobile-session-status') return status;
            return classElements[selector] || null;
        },
        querySelectorAll(selector) {
            return selector === '[data-mobile-view]' ? views : [];
        },
        addEventListener(name, listener) { documentListeners.set(name, listener); },
        removeEventListener(name, listener) {
            if (documentListeners.get(name) === listener) documentListeners.delete(name);
        },
    };
    const windowRef = {
        innerWidth: 390,
        matchMedia() { return {matches: true}; },
        requestAnimationFrame(callback) { callback(); },
        addEventListener(name, listener) { windowListeners.set(name, listener); },
        removeEventListener(name, listener) {
            if (windowListeners.get(name) === listener) windowListeners.delete(name);
        },
        i18n: {t(key) { return key; }},
    };
    const session = {
        id: 'active', host: 'prod.example', username: 'ops', connected: true,
    };
    const sessionManager = {
        getActiveSession() { return 'active'; },
        getSession(id) { return id === 'active' ? session : null; },
        getDisplayLabel() { return 'Production'; },
    };
    return {
        body, documentRef, windowRef, windowListeners, documentListeners,
        elements, views, status, sessionManager, classElements, focusState,
    };
}

test('phone shell keeps primary destinations and optional command input functional', () => {
    const {createController} = require('../../static/js/mobile-app-shell.js');
    const state = fixture();
    const controller = createController({
        window: state.windowRef,
        document: state.documentRef,
        sessionManager: state.sessionManager,
        terminalManager: {fitAndSyncVisibleTerminals() {}},
    });
    controller.init();

    assert.equal(state.elements.mobileSessionSummaryLabel.textContent, 'Production');
    assert.equal(state.status.classList.contains('connected'), true);
    assert.equal(state.elements.mobileCommandToggle.disabled, false);

    state.views.find(button => button.dataset.mobileView === 'hosts').dispatch('click');
    assert.equal(state.elements.manageProfilesBtn.clicks, 1);

    state.elements.mobileCommandToggle.dispatch('click');
    assert.equal(state.body.classList.contains('mobile-command-open'), true);
    assert.equal(state.elements.mobileInput.focused, true);

    state.elements.mobileInputCloseBtn.dispatch('click');
    assert.equal(state.body.classList.contains('mobile-command-open'), false);
    assert.equal(state.elements.mobileCommandToggle.getAttribute('aria-expanded'), 'false');

    state.views.find(button => button.dataset.mobileView === 'more').focus();
    state.views.find(button => button.dataset.mobileView === 'more').dispatch('click');
    assert.equal(state.elements.headerButtons.classList.contains('is-open'), true);
    assert.equal(state.elements.mobileMenuBackdrop.hidden, false);
    assert.equal(state.elements.headerButtons.getAttribute('role'), 'dialog');
    assert.equal(state.elements.headerButtons.getAttribute('aria-modal'), 'true');
    assert.equal(state.classElements['.main-content'].inert, true);
    assert.equal(state.documentRef.activeElement, state.elements.workspaceNavBtn);

    controller.destroy();
});

test('phone More dialog traps focus and restores the trigger on Escape', () => {
    const {createController} = require('../../static/js/mobile-app-shell.js');
    const state = fixture();
    const controller = createController({
        window: state.windowRef,
        document: state.documentRef,
        sessionManager: state.sessionManager,
    });
    controller.init();

    const more = state.views.find(button => button.dataset.mobileView === 'more');
    more.focus();
    more.dispatch('click');
    const last = state.elements.accountBtnHeader;
    last.focus();
    let prevented = false;
    state.documentListeners.get('keydown')({
        key: 'Tab',
        shiftKey: false,
        preventDefault() { prevented = true; },
    });
    assert.equal(prevented, true);
    assert.equal(state.documentRef.activeElement, state.elements.workspaceNavBtn);

    state.documentListeners.get('keydown')({key: 'Escape', preventDefault() {}});
    assert.equal(state.elements.headerButtons.classList.contains('is-open'), false);
    assert.equal(state.elements.headerButtons.getAttribute('role'), null);
    assert.equal(state.classElements['.main-content'].inert, false);
    assert.equal(state.documentRef.activeElement, more);
});

test('primary workspace changes keep the mobile dock selection synchronized', () => {
    const {createController} = require('../../static/js/mobile-app-shell.js');
    const state = fixture();
    const controller = createController({
        window: state.windowRef,
        document: state.documentRef,
        sessionManager: state.sessionManager,
    });
    controller.init();
    state.windowListeners.get('primary-workspace-change')({detail: {view: 'files'}});

    const files = state.views.find(button => button.dataset.mobileView === 'files');
    const terminal = state.views.find(button => button.dataset.mobileView === 'workspaces');
    assert.equal(files.classList.contains('active'), true);
    assert.equal(files.getAttribute('aria-current'), 'page');
    assert.equal(terminal.classList.contains('active'), false);
});

test('short coarse-pointer landscape keeps the phone shell above 767px', () => {
    const {createController} = require('../../static/js/mobile-app-shell.js');
    const state = fixture();
    state.windowRef.innerWidth = 844;
    state.windowRef.matchMedia = query => ({
        matches: query.includes('(max-height: 520px) and (pointer: coarse)'),
    });
    const controller = createController({
        window: state.windowRef,
        document: state.documentRef,
        sessionManager: state.sessionManager,
    });

    assert.equal(controller.isPhone(), true);
});
