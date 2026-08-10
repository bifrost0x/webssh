const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function loadSessionManager(confirmSessionClose = true) {
    const source = fs.readFileSync(
        path.join(__dirname, '..', '..', 'static', 'js', 'session-manager.js'),
        'utf8',
    );
    const context = {
        console,
        document: {
            body: {
                dataset: {
                    confirmSessionClose: String(confirmSessionClose),
                },
            },
            getElementById() {
                return null;
            },
        },
        TerminalManager: { destroyTerminal() {} },
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
    vm.createContext(context);
    vm.runInContext(`${source}\n;globalThis.__SessionManager = SessionManager;`, context);
    return { manager: context.__SessionManager, context };
}

function prepareSession(manager) {
    manager.sessions = {
        sessionA: { username: 'alice', host: 'example.test' },
    };
    manager.getDisplayLabel = () => 'alice@example.test';
}

test('explicit session close asks by default and respects cancellation', () => {
    const { manager, context } = loadSessionManager();
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
