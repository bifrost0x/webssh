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
        },
        window: {},
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
