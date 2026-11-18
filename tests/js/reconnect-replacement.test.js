const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

function setup() {
    const source = fs.readFileSync(path.join(__dirname, '../../static/js/app.js'), 'utf8');
    const handlers = {}, sent = [], removed = [], notices = [];
    const manager = {
        sessions: {old: {connected: true}}, pendingReconnectSessionId: 'old',
        createPendingConnection() {}, clearPendingConnection() {},
        createSession(data) { this.sessions[data.session_id] = {}; return data.session_id; },
        removeSessionUI(id) { removed.push(id); delete this.sessions[id]; },
        getFirstEmptyPaneIndex: () => 0, resolvePaneForNewSession: pane => pane ?? 0, assignSessionToPane() {},
    };
    let tick = 0;
    const fields = new Map();
    const field = id => {
        if (!fields.has(id)) fields.set(id, {value: '', addEventListener(_event, fn) {this.submit = fn;}});
        return fields.get(id);
    };
    for (const [id, value] of Object.entries({hostInput: 'private', portInput: '22', usernameInput: 'user',
        authTypeSelect: 'password', passwordInput: 'secret'})) field(id).value = value;
    const context = {SessionManager: manager, console, Uint32Array, Date: {now: () => ++tick},
        ConnectionHistory: {addConnection() {}},
        ConnectionCommandManager: {getPayload: () => ({})},
        refreshConnectionProfileJumpResolution: () => false, setInterval() {},
        document: {getElementById: field, querySelector: () => null},
        window: {crypto: {getRandomValues: a => a.fill(1)}, ModalManager: {close() {}}},
        socket: {on: (name, fn) => {handlers[name] = fn;}, emit: (name, data) => sent.push({name, data})},
        closeProfileManagementModal() {}, closeAuthBannerPrompt() {},
        stopConnectTimer() {}, setConnectLoading() {}, clearPendingPane() {},
        showNotification(message, type) { notices.push([message, type]); }, rememberTransientId(set, id) {set.add(id);},
        APP_ROOT: '',
    };
    vm.runInNewContext(`let selectedConnectionProfileState = null; let currentConnectRequestId = null, connectionModalRequestId = null, pendingPaneIndex = null, connectSeconds = 0, connectTimer = null;
        const pendingRequestPaneMap = new Map(), pendingReconnectSessionMap = new Map(), herdrFallbackNotified = new Set();
        const cancelledConnectRequestIds = new Set(), cancellingConnectRequestIds = new Set(), completedWhileCancellingRequestIds = new Set();
        function discardLateConnection() {}
    ` + source.slice(source.indexOf('    function startConnection('), source.indexOf('    function openConnectionModalForPane('))
        + source.slice(source.indexOf("    socket.on('ssh_connected'"), source.indexOf("    socket.on('ssh_output'"))
        + source.slice(source.indexOf("    socket.on('ssh_error'"), source.indexOf("    socket.on('ssh_disconnected'"))
        + source.slice(source.indexOf('    function finishConnectionCancellation('), source.indexOf('    function setPendingCancellationBusy('))
        + source.slice(source.indexOf("        document.getElementById('connectionForm').addEventListener('submit'"), source.indexOf("        document.getElementById('authTypeSelect').addEventListener('change'"))
        + '\nglobalThis.start = startConnection; globalThis.cancel = finishConnectionCancellation;', context);
    return {context, manager, handlers, sent, removed, notices, field, submit: () => field('connectionForm').submit({preventDefault() {}})};
}

test('successful form connection replaces only the original session and preserves attached tmux', () => {
    const {submit, handlers, sent, removed} = setup();
    submit();
    assert.deepEqual(removed, []);
    handlers.ssh_connected({session_id: 'new', client_request_id: sent[0].data.client_request_id});
    assert.deepEqual(removed, ['old']);
    assert.equal(sent[1].name, 'ssh_disconnect');
    assert.equal(sent[1].data.session_id, 'old');
    assert.equal(sent[1].data.preserve_tmux, true);
});

test('failed tmux form submission retains reconnect identity and name for retry', () => {
    const {manager, handlers, sent, field, submit} = setup();
    manager.pendingReconnectTmux = 'original-tmux';
    manager.pendingDisplayName = 'Original';
    field('useTmuxCheck').checked = true;
    submit();
    assert.equal(sent[0].data.reconnect_tmux_name, 'original-tmux');
    handlers.ssh_error({client_request_id: sent[0].data.client_request_id, error: 'bad password'});
    field('passwordInput').value = 'correct-password';
    submit();
    assert.equal(sent[1].data.reconnect_tmux_name, 'original-tmux');
    assert.equal(sent[1].data.display_name, 'Original');
    handlers.ssh_connected({session_id: 'new', client_request_id: sent[1].data.client_request_id});
    assert.equal(sent[2].data.replacement_session_id, 'new');
    assert.equal(manager.pendingReconnectTmux, null);
});

for (const outcome of ['error', 'cancel']) {
    test(`${outcome} preserves original and does not leak replacement into next request`, () => {
        const {context, handlers, sent, removed} = setup();
        context.start({host: 'private', port: 22, username: 'user'}, null, 'old');
        const id = sent[0].data.client_request_id;
        if (outcome === 'error') handlers.ssh_error({client_request_id: id, error: 'failed'});
        else context.cancel(id);
        assert.deepEqual(removed, []);
        context.start({host: 'other', port: 22, username: 'user'}, null);
        handlers.ssh_connected({session_id: 'new', client_request_id: sent[1].data.client_request_id});
        assert.deepEqual(removed, []);
        assert.equal(sent.filter(item => item.name === 'ssh_disconnect').length, 0);
    });
}

test('form connection of a Herdr host asks for the Herdr mode unless tmux or a startup command is chosen', () => {
    const utils = require('../../static/js/profile-launcher-utils.js');
    const request = prepare => {
        const {context, manager, sent, field, submit} = setup();
        context.window.ProfileLauncherUtils = utils;
        context.window.ProfileManager = {
            connectionProfileId: () => 'saved',
            getProfile: id => (id === 'saved' ? {id, herdr: true, use_herdr: true} : null),
        };
        prepare?.({context, manager, field});
        submit();
        return sent[0].data;
    };
    const plain = request();
    assert.equal(plain.use_herdr, true);
    assert.equal(plain.profile_id, 'saved');
    assert.equal(Object.hasOwn(plain, 'use_tmux'), false);
    const tmux = request(({field}) => { field('useTmuxCheck').checked = true; });
    assert.equal(tmux.use_tmux, true);
    assert.equal(Object.hasOwn(tmux, 'use_herdr'), false);
    const startup = request(({context}) => {
        context.ConnectionCommandManager.getPayload = () => ({startup_mode: 'free_text', startup_commands: 'pwd'});
    });
    assert.equal(Object.hasOwn(startup, 'use_herdr'), false);
    const other = request(({context}) => { context.window.ProfileManager.connectionProfileId = () => null; });
    assert.equal(Object.hasOwn(other, 'use_herdr'), false);
});

test('form reconnect of a Herdr session asks for the mode again and clears it after success', () => {
    const utils = require('../../static/js/profile-launcher-utils.js');
    const {context, manager, handlers, sent, submit} = setup();
    context.window.ProfileLauncherUtils = utils;
    manager.pendingReconnectProfileId = 'saved';
    manager.pendingReconnectHerdr = true;
    submit();
    assert.equal(sent[0].data.use_herdr, true);
    handlers.ssh_connected({session_id: 'new', client_request_id: sent[0].data.client_request_id});
    assert.equal(manager.pendingReconnectHerdr, false);
});

test('a missing Herdr is mentioned once per host, not on every reconnect', () => {
    const utils = require('../../static/js/profile-launcher-utils.js');
    const {context, handlers, sent, notices} = setup();
    context.window.ProfileLauncherUtils = utils;
    context.window.ProfileManager = {getProfile: id => ({id, herdr: true, use_herdr: true})};
    const connected = (sessionId, profileId, session) => {
        context.start({host: `${profileId}.example`, port: 22, username: 'user'}, null);
        handlers.ssh_connected({session_id: sessionId, client_request_id: sent.at(-1).data.client_request_id,
            host: `${profileId}.example`, profile_id: profileId, ...session});
    };
    connected('a', 'one', {herdr: true, use_herdr: false});
    connected('b', 'one', {herdr: true, use_herdr: false});
    connected('c', 'two', {herdr: true, use_herdr: true});
    connected('d', 'three', {herdr: false, use_herdr: false});
    const herdrNotices = () => notices.filter(([message]) => message.startsWith('Herdr'));
    assert.deepEqual(herdrNotices(), [['Herdr was not found on one.example. A standard shell was started instead.', 'info']]);
    connected('e', 'two', {herdr: true, use_herdr: false});
    assert.equal(herdrNotices().length, 2);
    assert.match(herdrNotices()[1][0], /two\.example/);
});
