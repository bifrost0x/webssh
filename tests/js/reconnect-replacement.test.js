const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

function setup() {
    const source = fs.readFileSync(path.join(__dirname, '../../static/js/app.js'), 'utf8');
    const handlers = {}, sent = [], removed = [];
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
        showNotification() {}, rememberTransientId(set, id) {set.add(id);},
        APP_ROOT: '',
    };
    vm.runInNewContext(`let currentConnectRequestId = null, connectionModalRequestId = null, pendingPaneIndex = null, connectSeconds = 0, connectTimer = null;
        const pendingRequestPaneMap = new Map(), pendingReconnectSessionMap = new Map();
        const cancelledConnectRequestIds = new Set(), cancellingConnectRequestIds = new Set(), completedWhileCancellingRequestIds = new Set();
        function discardLateConnection() {}
    ` + source.slice(source.indexOf('    function startConnection('), source.indexOf('    function openConnectionModalForPane('))
        + source.slice(source.indexOf("    socket.on('ssh_connected'"), source.indexOf("    socket.on('ssh_output'"))
        + source.slice(source.indexOf("    socket.on('ssh_error'"), source.indexOf("    socket.on('ssh_disconnected'"))
        + source.slice(source.indexOf('    function finishConnectionCancellation('), source.indexOf('    function setPendingCancellationBusy('))
        + source.slice(source.indexOf("        document.getElementById('connectionForm').addEventListener('submit'"), source.indexOf("        document.getElementById('authTypeSelect').addEventListener('change'"))
        + '\nglobalThis.start = startConnection; globalThis.cancel = finishConnectionCancellation;', context);
    return {context, manager, handlers, sent, removed, field, submit: () => field('connectionForm').submit({preventDefault() {}})};
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
