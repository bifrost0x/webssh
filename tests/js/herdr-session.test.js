const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const {buildSessionContext} = require('../../static/js/webssh2-shell.js');

function element(tagName = 'div') {
    const classes = new Set();
    return {
        tagName: tagName.toUpperCase(), children: [], dataset: {}, attributes: {}, value: '', checked: false,
        className: '', textContent: '', title: '',
        classList: {add: name => classes.add(name), remove: name => classes.delete(name), contains: name => classes.has(name)},
        appendChild(child) { this.children.push(child); return child; },
        insertBefore(child) { this.children.unshift(child); return child; },
        append(...nodes) { this.children.push(...nodes); },
        addEventListener() {}, dispatchEvent() {}, focus() {}, querySelector: () => null,
        setAttribute(name, value) { this.attributes[name] = String(value); },
    };
}

function loadManager({disconnectSessionAction = 'retry'} = {}) {
    const elements = new Map();
    const sent = [];
    const terminals = [];
    const context = {
        console,
        document: {
            body: {dataset: {disconnectSessionAction}},
            createElement: element,
            getElementById(id) {
                if (!elements.has(id)) elements.set(id, element());
                return elements.get(id);
            },
        },
        Event: function Event(type) { this.type = type; },
        TerminalManager: {
            createTerminal: (id, theme, options) => terminals.push({id, options}),
            attachTerminal() {}, setupInputHandler() {},
        },
        window: {
            socket: {emit: (event, payload) => sent.push({event, payload})},
            showNotification() {}, clearConnectionProfileState() {},
            prepareSessionReconnectJump: () => ({}),
        },
        confirm: () => true,
        setTimeout: fn => fn(),
    };
    vm.createContext(context);
    vm.runInContext(`${fs.readFileSync(path.join(__dirname, '../../static/js/session-manager.js'), 'utf8')}
;globalThis.manager = SessionManager;`, context);
    return {manager: context.manager, sent, terminals, field: id => context.document.getElementById(id)};
}

const herdrSession = {session_id: 'h', host: 'agents.example', port: 22, username: 'dev',
    profile_id: 'saved', herdr: true, use_herdr: true, use_tmux: false, key_id: 'key', auth_type: 'key'};

test('Herdr sessions keep OSC 52 clipboard writes off like a standard shell', () => {
    const {manager, terminals} = loadManager();
    manager.createSessionTab = () => {};
    manager.updateSessionStatus = () => {};
    manager.hideReconnectOverlay = () => {};
    manager.createSession(herdrSession);
    manager.createSession({...herdrSession, session_id: 'h2', tmux_session_name: 'leftover'});
    manager.createSession({session_id: 't', host: 'tmux.example', port: 22, username: 'dev',
        use_tmux: true, tmux_session_name: 'webssh_dev'});
    assert.deepEqual(terminals.map(item => [item.id, item.options.allowOsc52Clipboard]),
        [['h', false], ['h2', false], ['t', true]]);
});

test('a Herdr session tab carries its own Herdr badge instead of the tmux badge', () => {
    const {manager, field} = loadManager();
    manager.renderTabLabelContent = () => {};
    manager.scrollTabIntoView = () => {};
    manager.sessions.h = {host: 'agents.example', useHerdr: true, useTmux: false};
    manager.sessions.t = {host: 'tmux.example', useTmux: true, tmuxSessionName: 'main'};
    manager.sessions.s = {host: 'plain.example'};
    manager.createSessionTab('h');
    manager.createSessionTab('t');
    manager.createSessionTab('s');
    const badges = field('sessionTabs').children.map(tab => tab.children
        .filter(child => /tab-(tmux|herdr)-badge/.test(child.className))
        .map(child => ({className: child.className, icon: child.textContent, title: child.title})));
    assert.deepEqual(badges, [
        [{className: 'tab-herdr-badge material-icons', icon: 'view_quilt', title: 'Herdr'}],
        [{className: 'tab-tmux-badge material-icons', icon: 'push_pin', title: 'Persistent session (tmux): main'}],
        [],
    ]);
});

test('window chrome and the session summary name Herdr for a Herdr session', () => {
    const {manager} = loadManager();
    const chrome = [];
    manager.windowMode = true;
    manager.windowDesktop = {isOpen: () => true, setChrome: (index, value) => chrome.push(value)};
    manager.paneAssignments = ['h', 't'];
    manager.getDisplayLabel = () => 'label';
    manager.sessions.h = {host: 'agents.example', port: 22, username: 'dev', connected: true, useHerdr: true};
    manager.sessions.t = {host: 'tmux.example', port: 22, username: 'dev', connected: true, useTmux: true};
    manager.updateWindowChrome(0);
    manager.updateWindowChrome(1);
    assert.deepEqual(chrome.map(value => [...value.badges].map(badge => ({...badge}))), [
        [{icon: 'view_quilt', title: 'Herdr'}],
        [{icon: 'push_pin', title: 'tmux'}],
    ]);
    assert.equal(buildSessionContext({host: 'agents.example', useHerdr: true, connected: true}).persistence, 'Herdr');
});

test('a disconnected Herdr session is removed like a standard session when the preference says close', () => {
    for (const [session, removed] of [
        [{useHerdr: true, herdr: true}, true],
        [{}, true],
        [{useTmux: true, tmuxSessionName: 'main'}, false],
    ]) {
        const {manager} = loadManager({disconnectSessionAction: 'close'});
        manager.disconnectSessionAction = 'close';
        const calls = [];
        manager.sessions.a = {host: 'host.example', connected: true, ...session};
        manager.removeSessionUI = id => calls.push(id);
        manager.showReconnectOverlay = () => {};
        manager.refreshWindowChrome = () => {};
        manager.notifyWorkspaceChange = () => {};
        manager.updateSessionStatus('a', 'disconnected');
        assert.equal(calls.length === 1, removed, JSON.stringify(session));
    }
});

test('key reconnect of a Herdr session sends the Herdr mode with its profile and no tmux fields', () => {
    const {manager, sent} = loadManager();
    manager.getDisplayLabel = () => 'label';
    manager.closeSession = () => {};
    manager.reconnectRoute = () => ({});
    manager.sessions.h = {host: 'agents.example', port: 22, username: 'dev', connected: true,
        profileId: 'saved', herdr: true, useHerdr: true, keyId: 'key', authType: 'key'};
    manager.requestReconnect('h');
    const payload = sent[0].payload;
    assert.equal(payload.use_herdr, true);
    assert.equal(payload.profile_id, 'saved');
    for (const key of ['use_tmux', 'reconnect_tmux_name', 'tmux_session_name']) {
        assert.equal(Object.hasOwn(payload, key), false, key);
    }
});

test('form reconnect of a Herdr session clears a default tmux choice so Herdr is requested', () => {
    for (const viaPrefill of [false, true]) {
        const {manager, field} = loadManager();
        manager.getDisplayLabel = () => 'label';
        manager.closeSession = () => {};
        manager.removeSessionUI = () => {};
        manager.reconnectRoute = () => ({});
        field('useTmuxCheck').checked = true;
        manager.sessions.h = {host: 'agents.example', port: 22, username: 'dev', connected: true,
            profileId: 'saved', herdr: true, useHerdr: true, authType: 'password'};
        if (viaPrefill) manager.prefillConnectionForm('h');
        else manager.requestReconnect('h');
        assert.equal(field('useTmuxCheck').checked, false);
        assert.equal(manager.pendingReconnectHerdr, true);
        assert.equal(manager.pendingReconnectTmux, null);
    }
});
