const test = require('node:test');
const assert = require('node:assert/strict');

const {
    createAccountWorkspacePulse,
    getWorkspacePulseState,
} = require('../../static/js/account-workspace-pulse.js');

function sessionManager(overrides = {}) {
    return {
        sessions: {},
        paneAssignments: [],
        activeSessionId: null,
        getAllSessions() { return Object.values(this.sessions); },
        getActiveSession() { return this.activeSessionId; },
        getSession(id) { return this.sessions[id]; },
        ...overrides,
    };
}

function element() {
    const classes = new Set();
    return {
        textContent: '',
        dataset: {},
        classList: {
            toggle(name, enabled) {
                if (enabled) classes.add(name);
                else classes.delete(name);
            },
            contains(name) { return classes.has(name); },
        },
    };
}

test('returns a stable empty state when no SSH session is active', () => {
    assert.deepEqual(getWorkspacePulseState(sessionManager()), {
        connectedSessions: 0,
        occupiedPanes: 0,
        currentLabel: null,
        currentConnected: false,
    });
});

test('counts only connected sessions and occupied panes', () => {
    const manager = sessionManager({
        sessions: {
            alpha: { connected: true },
            beta: { connected: false },
            gamma: { connected: true },
        },
        paneAssignments: ['alpha', null, 'gamma', ''],
    });

    const state = getWorkspacePulseState(manager);

    assert.equal(state.connectedSessions, 2);
    assert.equal(state.occupiedPanes, 2);
});

test('prefers the active display name and falls back to username at host', () => {
    const manager = sessionManager({
        sessions: {
            alpha: { displayName: 'Production', username: 'ops', host: 'alpha.example', connected: true },
        },
        activeSessionId: 'alpha',
    });

    assert.equal(getWorkspacePulseState(manager).currentLabel, 'Production');
    manager.sessions.alpha.displayName = null;
    assert.equal(getWorkspacePulseState(manager).currentLabel, 'ops@alpha.example');
});

test('renders with textContent and refreshes on workspace and language changes', () => {
    const elements = {
        accountWorkspacePulse: element(),
        accountPulseSessions: element(),
        accountPulsePanes: element(),
        accountPulseCurrent: element(),
        accountPulseStatus: element(),
    };
    const listeners = {};
    const fakeWindow = {
        addEventListener(name, callback) { listeners[name] = callback; },
        removeEventListener() {},
    };
    const fakeDocument = {
        getElementById(id) { return elements[id] || null; },
    };
    const manager = sessionManager();
    const pulse = createAccountWorkspacePulse({
        sessionManager: manager,
        document: fakeDocument,
        window: fakeWindow,
        translate: key => key === 'account.noActiveSession' ? 'None active' : key,
    });

    assert.equal(pulse.init(), true);
    assert.equal(elements.accountPulseCurrent.textContent, 'None active');

    manager.sessions.alpha = {
        displayName: '<b>Production</b>',
        username: 'ops',
        host: 'alpha.example',
        connected: true,
    };
    manager.activeSessionId = 'alpha';
    manager.paneAssignments = ['alpha'];
    listeners['session-workspace-change']();

    assert.equal(elements.accountPulseSessions.textContent, '1');
    assert.equal(elements.accountPulsePanes.textContent, '1');
    assert.equal(elements.accountPulseCurrent.textContent, '<b>Production</b>');
    assert.equal(elements.accountPulseStatus.classList.contains('is-connected'), true);

    listeners.languageChanged();
    assert.equal(elements.accountPulseCurrent.textContent, '<b>Production</b>');
});
