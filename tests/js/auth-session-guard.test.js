const assert = require('node:assert/strict');
const test = require('node:test');
const guardModule = require('../../static/js/auth-session-guard.js');
const notepadModule = require('../../static/js/notepad-controller.js');

function storage() {
    const values = new Map();
    return {
        get length() { return values.size; },
        key: index => Array.from(values.keys())[index] ?? null,
        getItem: key => values.get(key) || null,
        setItem: (key, value) => values.set(key, value),
        removeItem: key => values.delete(key),
    };
}

test('warns before web authentication expiry and distinguishes it from SSH idle', () => {
    const notices = [];
    const timers = [];
    const browserWindow = {
        document: {body: {dataset: {}}, getElementById() { return null; }},
        sessionStorage: storage(),
        location: {pathname: '/', search: '', hash: '', assign() {}},
        showNotification(value) { notices.push(value); return () => {}; },
        setTimeout(callback, delay) { timers.push({callback, delay}); return timers.length; },
    };
    const guard = guardModule.create({
        window: browserWindow,
        document: browserWindow.document,
        expiresAt: 1000 + (4 * 60 * 1000),
        now: () => 1000,
        setTimeout: browserWindow.setTimeout,
    });
    guard.schedule();
    assert.equal(notices.length, 1);
    assert.match(notices[0].message, /separate from the SSH idle timeout/);
    assert.equal(notices[0].persistent, true);
    assert.equal(timers[0].delay, 3 * 60 * 1000);
});

test('acknowledging warnings does not repeat or postpone authentication expiry', () => {
    let currentTime = 1000;
    const notices = [];
    const timers = [];
    const redirects = [];
    const browserWindow = {
        document: {body: {dataset: {}}, getElementById() { return null; }},
        sessionStorage: storage(),
        location: {pathname: '/', search: '', hash: '', assign: value => redirects.push(value)},
        i18n: {t: key => key === 'common.close' ? 'Schließen' : key},
        showNotification(value) { notices.push(value); return () => {}; },
        setTimeout(callback, delay) { timers.push({callback, delay}); return timers.length; },
    };
    const guard = guardModule.create({
        window: browserWindow, expiresAt: 301000, serverNow: 1000,
        now: () => currentTime,
    });
    guard.schedule();
    assert.equal(notices[0].action.label, 'Schließen');
    notices[0].action.onClick();
    assert.equal(timers[0].delay, 240000);
    guard.schedule();
    assert.equal(notices.length, 1);

    currentTime += 240000;
    timers[0].callback();
    assert.equal(notices.length, 2);
    assert.equal(notices[1].type, 'warning');
    notices[1].action.onClick();
    assert.equal(timers.at(-1).delay, 60000);
    assert.deepEqual(redirects, []);
    currentTime += 60000;
    timers.at(-1).callback();
    assert.deepEqual(redirects, ['/login?next=%2F']);
    assert.equal(browserWindow.authSessionRedirectPending, true);
});

test('expiry stores workspace context before returning to login', () => {
    const assigned = [];
    const sessionStorage = storage();
    const accountScope = 'account-a-scope';
    const note = {value: 'unfinished note'};
    const browserDocument = {
        body: {dataset: {primaryWorkspace: 'workspaces', connectionHistoryScope: accountScope}},
        getElementById(id) { return id === 'sessionNotepad' ? note : null; },
    };
    const browserWindow = {
        document: browserDocument, sessionStorage,
        APP_ROOT: '/ssh', authSessionRedirectPending: false,
        location: {pathname: '/', search: '?view=1', hash: '#current', assign: value => assigned.push(value)},
        SessionManager: {getActiveSession: () => 'session-a'},
        workspaceLayoutController: {getState: () => ({activeContext: 'files'})},
        notepadController: {hasUnsaved: () => true},
        SessionCommandLauncher: {parameterDrafts: new Map([['command-a', '--draft']])},
        setTimeout() {},
    };
    const guard = guardModule.create({
        window: browserWindow, document: browserDocument, storage: sessionStorage,
        expiresAt: 0, now: () => 1234, setTimeout() {},
    });
    guard.expire();
    assert.equal(browserWindow.authSessionRedirectPending, true);
    assert.deepEqual(assigned, ['/ssh/login?next=%2F%3Fview%3D1']);
    assert.deepEqual(guardModule.readRestore(sessionStorage, 1234, accountScope), {
        accountScope, savedAt: 1234, path: '/?view=1#current', sessionId: 'session-a',
        primaryView: 'workspaces', activeContext: 'files', noteDraft: 'unfinished note',
        layout: null, paneAssignments: [], commandDrafts: [['command-a', '--draft']],
    });
});

test('restore state remains available only to the account that created it', () => {
    const sessionStorage = storage();
    const accountAScope = 'account-a-scope';
    const accountBScope = 'account-b-scope';
    const sourceDocument = {
        body: {dataset: {primaryWorkspace: 'workspaces', connectionHistoryScope: accountAScope}},
        getElementById: id => id === 'sessionNotepad'
            ? {value: 'private account A draft'} : null,
    };
    guardModule.saveRestore({
        location: {pathname: '/', search: '', hash: ''},
        SessionManager: {getActiveSession: () => null, layout: 1, paneAssignments: []},
        notepadController: {hasUnsaved: () => true},
        SessionCommandLauncher: {
            parameterDrafts: new Map([['command-secret', '--token=A']]),
        },
    }, sourceDocument, sessionStorage, Date.now(), accountAScope);

    const emitted = [];
    const socket = {
        connected: false,
        on() {},
        emit(event, payload) { emitted.push([event, payload]); },
    };
    let accountBInputEvents = 0;
    let accountBController;
    const accountBNote = {
        value: 'account B note',
        dispatchEvent() {
            accountBInputEvents += 1;
            accountBController.changed();
        },
    };
    const accountBDocument = {
        body: {dataset: {connectionHistoryScope: accountBScope}},
        getElementById: id => id === 'sessionNotepad' ? accountBNote : null,
    };
    accountBController = notepadModule.create({
        socket,
        read: () => accountBNote.value,
        write: value => { accountBNote.value = value; },
        status() {},
        setTimeout() { return 1; },
        clearTimeout() {},
    });
    const accountBWindow = {
        Event: class {},
        SessionCommandLauncher: {parameterDrafts: new Map([['own-command', 'own draft']])},
    };

    assert.equal(
        guardModule.restore(accountBWindow, accountBDocument, sessionStorage),
        false,
    );
    assert.equal(accountBNote.value, 'account B note');
    assert.equal(accountBInputEvents, 0);
    assert.deepEqual(
        Array.from(accountBWindow.SessionCommandLauncher.parameterDrafts.entries()),
        [['own-command', 'own draft']],
    );
    assert.equal(
        guardModule.readRestore(sessionStorage, Date.now(), accountAScope),
        null,
    );
    socket.connected = true;
    accountBController.reconnect();
    assert.deepEqual(emitted, []);
});

test('matching account restores unsaved drafts and consumes the record', () => {
    const sessionStorage = storage();
    const accountScope = 'account-a-scope';
    const sourceDocument = {
        body: {dataset: {primaryWorkspace: 'workspaces', connectionHistoryScope: accountScope}},
        getElementById: id => id === 'sessionNotepad' ? {value: 'unfinished note'} : null,
    };
    guardModule.saveRestore({
        location: {pathname: '/', search: '?view=1', hash: '#current'},
        SessionManager: {getActiveSession: () => null, layout: 1, paneAssignments: []},
        notepadController: {hasUnsaved: () => true},
        SessionCommandLauncher: {parameterDrafts: new Map([['command-a', '--draft']])},
    }, sourceDocument, sessionStorage, Date.now(), accountScope);

    let inputEvents = 0;
    let restoredPath = null;
    const note = {
        value: '',
        dispatchEvent() { inputEvents += 1; },
    };
    const browserDocument = {
        body: {dataset: {connectionHistoryScope: accountScope}},
        getElementById: id => id === 'sessionNotepad' ? note : null,
    };
    const browserWindow = {
        Event: class {},
        history: {replaceState(_state, _title, path) { restoredPath = path; }},
        SessionManager: {setSplitLayout() {}, getSession: () => null},
        SessionCommandLauncher: {parameterDrafts: new Map()},
        primaryWorkspaceController: {showWorkspaces() {}},
    };

    assert.equal(guardModule.restore(browserWindow, browserDocument, sessionStorage), true);
    assert.equal(note.value, 'unfinished note');
    assert.equal(inputEvents, 1);
    assert.equal(restoredPath, '/?view=1#current');
    assert.deepEqual(
        Array.from(browserWindow.SessionCommandLauncher.parameterDrafts.entries()),
        [['command-a', '--draft']],
    );
    assert.equal(
        guardModule.readRestore(sessionStorage, Date.now(), accountScope),
        null,
    );
});

test('missing scope and legacy unscoped records fail closed', () => {
    const sessionStorage = storage();
    sessionStorage.setItem('webssh:auth-session-return', JSON.stringify({
        savedAt: Date.now(),
        noteDraft: 'legacy account draft',
    }));
    const browserDocument = {
        body: {dataset: {}},
        getElementById() { return null; },
    };

    assert.equal(guardModule.restore({Event: class {}}, browserDocument, sessionStorage), false);
    assert.equal(sessionStorage.getItem('webssh:auth-session-return'), null);

    guardModule.saveRestore({
        location: {pathname: '/', search: '', hash: ''},
    }, browserDocument, sessionStorage, Date.now());
    assert.equal(guardModule.readRestore(sessionStorage, Date.now()), null);
});

test('a copied restore record with another account stamp is rejected', () => {
    const sessionStorage = storage();
    const accountAScope = 'account-a-scope';
    const accountBScope = 'account-b-scope';
    const browserDocument = {
        body: {dataset: {connectionHistoryScope: accountAScope}},
        getElementById() { return null; },
    };
    guardModule.saveRestore({
        location: {pathname: '/', search: '', hash: ''},
    }, browserDocument, sessionStorage, Date.now(), accountAScope);
    const accountARecord = sessionStorage.getItem(
        `webssh:auth-session-return:${accountAScope}`,
    );
    sessionStorage.setItem(
        `webssh:auth-session-return:${accountBScope}`,
        accountARecord,
    );

    assert.equal(
        guardModule.readRestore(sessionStorage, Date.now(), accountBScope),
        null,
    );
});

test('saving a new account prunes prior restore state before writing', () => {
    const values = new Map();
    const sessionStorage = {
        get length() { return values.size; },
        key: index => Array.from(values.keys())[index] ?? null,
        getItem: key => values.get(key) || null,
        setItem(key, value) {
            if (!values.has(key) && values.size >= 1) throw new Error('quota exceeded');
            values.set(key, value);
        },
        removeItem: key => values.delete(key),
    };
    const browserWindow = {
        location: {pathname: '/', search: '', hash: ''},
    };
    const browserDocument = {
        body: {dataset: {}},
        getElementById() { return null; },
    };

    guardModule.saveRestore(
        browserWindow,
        browserDocument,
        sessionStorage,
        Date.now(),
        'account-a-scope',
    );
    guardModule.saveRestore(
        browserWindow,
        browserDocument,
        sessionStorage,
        Date.now(),
        'account-b-scope',
    );

    assert.equal(
        sessionStorage.getItem('webssh:auth-session-return:account-a-scope'),
        null,
    );
    assert.notEqual(
        guardModule.readRestore(sessionStorage, Date.now(), 'account-b-scope'),
        null,
    );
});

for (const view of ['overview', 'workspaces']) {
    test(`reauthentication restores ${view} with asynchronously arriving window sessions without recursion`, () => {
        const sessionStorage = storage();
        const accountScope = 'window-account';
        const document = {
            body: {dataset: {primaryWorkspace: view, connectionHistoryScope: accountScope}},
            getElementById: id => id === 'overviewNavBtn' ? {click() { selected = 'overview'; }} : null,
        };
        guardModule.saveRestore({
            location: {pathname: '/', search: '', hash: ''},
            SessionManager: {getActiveSession: () => 'later', layout: 'windows', paneAssignments: ['later']},
        }, document, sessionStorage);
        let selected = null;
        let listener = null;
        let session = null;
        let switches = 0;
        const browser = {
            primaryWorkspaceController: {showWorkspaces() { selected = 'workspaces'; }},
            SessionManager: {
                setSplitLayout(layout) { assert.equal(layout, 'windows'); listener?.(); },
                getSession: () => session,
                switchSession(id) { assert.equal(id, 'later'); switches++; listener?.(); },
                assignSessionToPane() { assert.fail('window placement is owned by the desktop'); },
            },
            addEventListener(_name, fn) { listener = fn; },
            removeEventListener() { listener = null; },
        };
        assert.equal(guardModule.restore(browser, document, sessionStorage), true);
        assert.equal(selected, view);
        session = {id: 'later'};
        listener();
        assert.equal(switches, 1);
        assert.equal(listener, null);
    });
}
