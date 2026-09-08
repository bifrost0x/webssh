const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function createElement(tagName = 'div') {
    const classes = new Set();
    const listeners = new Map();
    const element = {
        tagName: tagName.toUpperCase(),
        children: [],
        parentNode: null,
        dataset: {},
        attributes: {},
        hidden: false,
        textContent: '',
        className: '',
        classList: {
            add(...values) { values.forEach(value => classes.add(value)); },
            remove(...values) { values.forEach(value => classes.delete(value)); },
            contains(value) { return classes.has(value); },
            toggle(value, force) {
                const next = force === undefined ? !classes.has(value) : Boolean(force);
                if (next) classes.add(value);
                else classes.delete(value);
                return next;
            },
        },
        appendChild(child) {
            child.parentNode?.removeChild?.(child);
            child.parentNode = this;
            this.children.push(child);
            return child;
        },
        removeChild(child) {
            this.children = this.children.filter(candidate => candidate !== child);
            child.parentNode = null;
        },
        remove() { this.parentNode?.removeChild?.(this); },
        addEventListener(type, handler) { listeners.set(type, handler); },
        click() {
            listeners.get('click')?.({
                target: this,
                stopPropagation() {},
            });
        },
        pressKey(key) {
            if (this.tagName === 'BUTTON' && ['Enter', ' '].includes(key)) {
                this.click();
            }
        },
        setAttribute(name, value) {
            this.attributes[name] = String(value);
        },
        querySelector(selector) {
            return this.querySelectorAll(selector)[0] || null;
        },
        querySelectorAll(selector) {
            const matches = [];
            const visit = node => {
                const classNames = String(node.className || '').split(/\s+/).filter(Boolean);
                const matchesSelector = selector.startsWith('.')
                    ? classNames.includes(selector.slice(1))
                    : node.tagName === selector.toUpperCase();
                if (matchesSelector) matches.push(node);
                node.children.forEach(visit);
            };
            this.children.forEach(visit);
            return matches;
        },
    };
    return element;
}

function loadSessionManager(
    confirmSessionClose,
    disconnectSessionAction,
    connectionHistoryScope = '',
) {
    const source = fs.readFileSync(
        path.join(__dirname, '..', '..', 'static', 'js', 'session-manager.js'),
        'utf8',
    );
    const elements = new Map();
    const body = createElement('body');
    body.dataset = {
        confirmSessionClose: String(confirmSessionClose),
        disconnectSessionAction: disconnectSessionAction || '',
        connectionHistoryScope,
    };
    const stored = new Map();
    const localStorage = {
        get length() { return stored.size; },
        key(index) { return Array.from(stored.keys())[index] ?? null; },
        getItem(key) { return stored.has(key) ? stored.get(key) : null; },
        setItem(key, value) { stored.set(String(key), String(value)); },
        removeItem(key) { stored.delete(String(key)); },
    };
    const context = {
        console,
        localStorage,
        document: {
            body,
            createElement,
            getElementById(id) {
                if (elements.has(id)) return elements.get(id);
                const findById = node => {
                    if (node.id === id) return node;
                    for (const child of node.children || []) {
                        const match = findById(child);
                        if (match) return match;
                    }
                    return null;
                };
                for (const root of elements.values()) {
                    const match = findById(root);
                    if (match) return match;
                }
                return null;
            },
        },
        TerminalManager: {
            destroyTerminal() {},
            resyncRestoredOutput() {},
            seedRestoredOutput() {},
        },
        CustomEvent: class CustomEvent {
            constructor(type, options) {
                this.type = type;
                this.detail = options?.detail;
            }
        },
        window: {
            dispatchEvent(event) {
                const listeners = this.listeners?.get(event.type) || [];
                listeners.forEach(listener => listener(event));
                return true;
            },
            addEventListener(type, listener) {
                this.listeners = this.listeners || new Map();
                this.listeners.set(type, [...(this.listeners.get(type) || []), listener]);
            },
        },
    };
    context.window.window = context.window;
    context.window.CustomEvent = context.CustomEvent;
    vm.createContext(context);
    vm.runInContext(`${source}\n;globalThis.__SessionManager = SessionManager;`, context);
    return {
        manager: context.__SessionManager,
        context,
        localStorage,
        createElement,
        registerElement(id, element) {
            element.id = id;
            elements.set(id, element);
            return element;
        },
    };
}

test('account-scoped aliases stay isolated and survive account switching', () => {
    const {
        manager, context, localStorage,
    } = loadSessionManager(false, 'retry', 'account-b-scope');
    localStorage.setItem('sessionDisplayNames', JSON.stringify({leak: 'legacy'}));
    localStorage.setItem(
        'sessionDisplayNames:account-a-scope',
        JSON.stringify({target: 'Customer A production'}),
    );
    localStorage.setItem('sessionDisplayNames:activeScope', 'account-a-scope');

    manager.initializeDisplayNameStorage();

    assert.equal(localStorage.getItem('sessionDisplayNames'), null);
    assert.equal(
        localStorage.getItem('sessionDisplayNames:account-a-scope'),
        JSON.stringify({target: 'Customer A production'}),
    );

    manager.writeDisplayNames({target: 'Customer B production'});
    assert.deepEqual(JSON.parse(JSON.stringify(manager.readDisplayNames())), {
        target: 'Customer B production',
    });

    context.document.body.dataset.connectionHistoryScope = 'account-a-scope';
    manager.initializeDisplayNameStorage();
    assert.equal(
        localStorage.getItem('sessionDisplayNames:account-b-scope'),
        JSON.stringify({target: 'Customer B production'}),
    );
    assert.deepEqual(JSON.parse(JSON.stringify(manager.readDisplayNames())), {
        target: 'Customer A production',
    });
});

test('explicit logout retains namespaced convenience data', () => {
    const {manager, localStorage} = loadSessionManager(
        false, 'retry', 'account-a-scope'
    );
    localStorage.setItem(
        'sessionDisplayNames:account-a-scope',
        JSON.stringify({target: 'Sensitive alias'}),
    );
    localStorage.setItem(
        'recentConnections:account-a-scope',
        JSON.stringify([{host: 'target'}]),
    );
    localStorage.setItem('sessionDisplayNames:activeScope', 'account-a-scope');

    manager.clearScopedBrowserStorage();

    assert.equal(
        localStorage.getItem('sessionDisplayNames:account-a-scope'),
        JSON.stringify({target: 'Sensitive alias'}),
    );
    assert.equal(
        localStorage.getItem('recentConnections:account-a-scope'),
        JSON.stringify([{host: 'target'}]),
    );
    assert.equal(
        localStorage.getItem('sessionDisplayNames:activeScope'),
        null,
    );
});

test('connection launcher stages replacement without unassigning the live session', () => {
    const {
        manager, context, createElement, registerElement,
    } = loadSessionManager(false, 'retry');
    const terminalsContainer = registerElement('terminalsContainer', createElement());
    const pane = createElement();
    const terminal = registerElement('terminal-session-a', createElement());
    pane.appendChild(terminal);
    manager.sessions = {
        'session-a': {
            id: 'session-a',
            terminalId: 'terminal-session-a',
        },
    };
    manager.paneAssignments = ['session-a'];
    const rendered = [];
    const activated = [];
    let searchClosed = 0;
    context.window.TerminalSearch = {
        isOpen: true,
        close() { searchClosed += 1; },
    };
    manager.renderPane = paneIndex => rendered.push(paneIndex);
    manager.setActivePane = paneIndex => activated.push(paneIndex);

    assert.equal(manager.showConnectionLauncher(0), true);

    assert.deepEqual(manager.paneAssignments, ['session-a']);
    assert.equal(manager.connectionLauncherSessions.get(0), 'session-a');
    assert.equal(terminal.parentNode, terminalsContainer);
    assert.equal(terminal.classList.contains('unassigned'), true);
    assert.equal(manager.sessions['session-a'].id, 'session-a');
    assert.equal(searchClosed, 1);
    assert.deepEqual(rendered, [0]);
    assert.deepEqual(activated, [0]);

    assert.equal(manager.restoreConnectionLauncher(0), true);
    assert.equal(manager.connectionLauncherSessions.has(0), false);
    assert.deepEqual(manager.paneAssignments, ['session-a']);
    assert.deepEqual(rendered, [0, 0]);
    assert.deepEqual(activated, [0, 0]);
});

test('connection launcher rejects a pane outside the current layout', () => {
    const {manager} = loadSessionManager(false, 'retry');
    manager.paneAssignments = [null];

    assert.equal(manager.showConnectionLauncher(1), false);
    assert.deepEqual(manager.paneAssignments, [null]);
});

test('pending close requests cancellation and waits for acknowledgement', () => {
    const {
        manager, context, registerElement,
    } = loadSessionManager(false, 'retry');
    const sessionTabs = registerElement('sessionTabs', createElement());
    const cancellationRequests = [];
    context.window.addEventListener('ssh-connection-cancel-requested', event => {
        cancellationRequests.push(event.detail.requestId);
    });

    manager.createPendingConnection('request-a', 'a.example', 'alice', 22);
    manager.createPendingConnection('request-b', 'b.example', 'bob', 2222);

    const requestATab = sessionTabs.children.find(
        child => child.dataset.pendingId === 'request-a'
    );
    const requestAClose = requestATab.querySelector('.tab-close');
    assert.equal(requestAClose.tagName, 'BUTTON');
    assert.equal(requestAClose.type, 'button');

    requestAClose.click();

    assert.deepEqual(cancellationRequests, ['request-a']);
    assert.deepEqual(
        JSON.parse(JSON.stringify(manager.pendingConnections['request-a'])),
        {
            host: 'a.example',
            username: 'alice',
            port: 22,
        },
    );
    assert.deepEqual(
        JSON.parse(JSON.stringify(manager.pendingConnections['request-b'])),
        {
            host: 'b.example',
            username: 'bob',
            port: 2222,
        },
    );
    assert.equal(
        sessionTabs.children.some(child => child.dataset.pendingId === 'request-a'),
        true,
    );
    assert.equal(
        sessionTabs.children.some(child => child.dataset.pendingId === 'request-b'),
        true,
    );

    manager.clearPendingConnection('request-a');
    assert.equal(manager.pendingConnections['request-a'], undefined);
    assert.equal(
        sessionTabs.children.some(child => child.dataset.pendingId === 'request-a'),
        false,
    );
});

test('pending connection close supports native keyboard activation', () => {
    const {
        manager, context, registerElement,
    } = loadSessionManager(false, 'retry');
    const sessionTabs = registerElement('sessionTabs', createElement());
    const cancellationRequests = [];
    context.window.addEventListener('ssh-connection-cancel-requested', event => {
        cancellationRequests.push(event.detail.requestId);
    });

    manager.createPendingConnection('request-enter', 'enter.example', 'alice', 22);
    manager.createPendingConnection('request-space', 'space.example', 'bob', 22);
    manager.createPendingConnection('request-other', 'other.example', 'carol', 22);

    const closeFor = requestId => sessionTabs.children.find(
        child => child.dataset.pendingId === requestId
    ).querySelector('.tab-close');
    closeFor('request-enter').pressKey('Enter');
    closeFor('request-space').pressKey(' ');

    assert.deepEqual(cancellationRequests, ['request-enter', 'request-space']);
    assert.notEqual(manager.pendingConnections['request-enter'], undefined);
    assert.notEqual(manager.pendingConnections['request-space'], undefined);
    assert.deepEqual(
        JSON.parse(JSON.stringify(manager.pendingConnections['request-other'])),
        {
            host: 'other.example',
            username: 'carol',
            port: 22,
        },
    );
    assert.equal(
        sessionTabs.children.some(
            child => child.dataset.pendingId === 'request-other'
        ),
        true,
    );

    manager.clearPendingConnection('request-enter');
    manager.clearPendingConnection('request-space');
    assert.equal(manager.pendingConnections['request-enter'], undefined);
    assert.equal(manager.pendingConnections['request-space'], undefined);
});

test('workspace notifications retain the staged session as the active context', () => {
    const {manager, context} = loadSessionManager(false, 'retry');
    manager.sessions = {'session-a': {id: 'session-a'}};
    manager.paneAssignments = ['session-a'];
    manager.activePaneIndex = 0;
    manager.activeSessionId = 'session-a';
    manager.connectionLauncherSessions.set(0, 'session-a');
    let detail = null;
    context.window.addEventListener('session-workspace-change', event => {
        detail = event.detail;
    });

    manager.notifyWorkspaceChange();

    assert.deepEqual(JSON.parse(JSON.stringify(detail)), {
        layout: 1,
        sessionId: 'session-a',
    });
});

test('successful assignment commits a staged pane replacement', () => {
    const {manager} = loadSessionManager(false, 'retry');
    manager.sessions = {
        'session-a': {id: 'session-a', terminalId: 'terminal-session-a'},
        'session-b': {id: 'session-b', terminalId: 'terminal-session-b'},
    };
    manager.paneAssignments = ['session-a'];
    manager.connectionLauncherSessions.set(0, 'session-a');
    const rendered = [];
    const activated = [];
    manager.renderPane = paneIndex => rendered.push(paneIndex);
    manager.setActivePane = paneIndex => activated.push(paneIndex);

    manager.assignSessionToPane('session-b', 0);

    assert.deepEqual(manager.paneAssignments, ['session-b']);
    assert.equal(manager.connectionLauncherSessions.has(0), false);
    assert.deepEqual(rendered, [0]);
    assert.deepEqual(activated, [0]);
});

function prepareSession(manager) {
    manager.sessions = {
        sessionA: { username: 'alice', host: 'example.test' },
    };
    manager.getDisplayLabel = () => 'alice@example.test';
}

test('enabled close confirmation asks and respects cancellation', () => {
    const { manager, context } = loadSessionManager(true);
    prepareSession(manager);
    let confirmCalls = 0;
    let closeCalls = 0;
    context.confirm = () => {
        confirmCalls += 1;
        return false;
    };
    manager.closeSession = () => { closeCalls += 1; };

    manager.requestCloseSession('sessionA');

    assert.equal(confirmCalls, 1);
    assert.equal(closeCalls, 0);
});

test('missing close confirmation preference defaults to disabled', () => {
    const { manager } = loadSessionManager();

    assert.equal(manager.confirmSessionClose, false);
});

test('missing disconnect preference keeps the backward-compatible retry behavior', () => {
    const { manager } = loadSessionManager();

    assert.equal(manager.disconnectSessionAction, 'retry');
});

test('disabled close confirmation closes directly without calling confirm', () => {
    const { manager, context } = loadSessionManager(false);
    prepareSession(manager);
    let confirmCalls = 0;
    let closeCalls = 0;
    context.confirm = () => {
        confirmCalls += 1;
        return true;
    };
    manager.closeSession = () => { closeCalls += 1; };

    manager.requestCloseSession('sessionA');

    assert.equal(confirmCalls, 0);
    assert.equal(closeCalls, 1);
});

test('emits a session-removed event exactly once for each actual UI removal', () => {
    const { manager, context } = loadSessionManager();
    prepareSession(manager);
    manager.paneAssignments = [];
    manager.updateSessionMeta = () => {};
    manager.notifyWorkspaceChange = () => {};
    const removedIds = [];
    context.window.addEventListener('session-removed', event => removedIds.push(event.detail.sessionId));

    manager.removeSessionUI('sessionA');
    assert.deepEqual(removedIds, ['sessionA']);
    manager.removeSessionUI('missing-session');
    assert.deepEqual(removedIds, ['sessionA']);
});

test('close disconnect preference removes a normal disconnected tab and switches away', () => {
    const { manager } = loadSessionManager(false, 'close');
    prepareSession(manager);
    const calls = [];
    manager.showReconnectOverlay = id => calls.push(['overlay', id]);
    manager.removeSessionUI = id => calls.push(['remove', id]);
    manager.notifyWorkspaceChange = () => calls.push(['workspace']);

    manager.updateSessionStatus('sessionA', 'disconnected');

    assert.deepEqual(calls, [['remove', 'sessionA']]);
});

test('close disconnect preference preserves persistent reconnect candidates', () => {
    const { manager } = loadSessionManager(false, 'close');
    prepareSession(manager);
    manager.sessions.sessionA.isPersistentCandidate = true;
    const calls = [];
    manager.showReconnectOverlay = id => calls.push(['overlay', id]);
    manager.removeSessionUI = id => calls.push(['remove', id]);
    manager.notifyWorkspaceChange = () => calls.push(['workspace']);

    manager.updateSessionStatus('sessionA', 'disconnected');

    assert.deepEqual(calls, [['overlay', 'sessionA'], ['workspace']]);
});

test('close disconnect preference preserves live tmux sessions', () => {
    const { manager } = loadSessionManager(false, 'close');
    prepareSession(manager);
    manager.sessions.sessionA.useTmux = true;
    manager.sessions.sessionA.tmuxSessionName = 'webssh-alice';
    const calls = [];
    manager.showReconnectOverlay = id => calls.push(['overlay', id]);
    manager.removeSessionUI = id => calls.push(['remove', id]);
    manager.notifyWorkspaceChange = () => calls.push(['workspace']);

    manager.updateSessionStatus('sessionA', 'disconnected');

    assert.deepEqual(calls, [['overlay', 'sessionA'], ['workspace']]);
});

test('retry overlay closes the server session when the user dismisses the tab', () => {
    const {
        manager, registerElement, createElement: makeElement,
    } = loadSessionManager(false, 'retry');
    const terminal = registerElement('terminal-sessionA', makeElement('div'));
    manager.sessions = {
        sessionA: {
            username: 'alice',
            host: 'example.test',
            terminalId: 'terminal-sessionA',
            connected: false,
        },
    };
    const closed = [];
    manager.closeSession = id => closed.push(id);

    manager.showReconnectOverlay('sessionA');

    const buttons = terminal.querySelectorAll('button');
    assert.deepEqual(buttons.map(button => button.textContent), ['Retry', 'Close tab']);
    buttons[1].click();
    assert.deepEqual(closed, ['sessionA']);
});

test('seeds restored output before creating and attaching the terminal', () => {
    const { manager, context } = loadSessionManager();
    const calls = [];
    context.TerminalManager.seedRestoredOutput = (sessionId, output, sequence) => {
        calls.push(['seed', sessionId, output, sequence]);
    };
    manager.createSession = data => {
        calls.push([
            'create',
            data.session_id,
            data.restored,
            data.use_tmux,
            data.tmux_session_name,
        ]);
        return data.session_id;
    };
    manager.getFirstEmptyPaneIndex = () => 0;
    manager.assignSessionToPane = sessionId => calls.push(['assign', sessionId]);

    manager.restoreSession({
        session_id: 'restored',
        host: 'switch.test',
        port: 22,
        username: 'admin',
        buffered_output: 'switch# ',
        output_sequence: 14,
        use_tmux: true,
        tmux_session_name: 'webssh_admin_switch',
    });

    assert.deepEqual(calls, [
        ['seed', 'restored', 'switch# ', 14],
        ['create', 'restored', true, true, 'webssh_admin_switch'],
        ['assign', 'restored'],
    ]);
});

test('resyncs an existing restored session without recreating its tab', () => {
    const { manager, context } = loadSessionManager();
    const calls = [];
    manager.sessions.restored = {id: 'restored', connected: true};
    context.TerminalManager.resyncRestoredOutput = (
        sessionId, output, sequence
    ) => calls.push(['resync', sessionId, output, sequence]);
    manager.createSession = () => calls.push(['create']);

    manager.restoreSession({
        session_id: 'restored',
        buffered_output: 'switch# ',
        output_sequence: 14,
    });

    assert.deepEqual(calls, [
        ['resync', 'restored', 'switch# ', 14],
    ]);
});
