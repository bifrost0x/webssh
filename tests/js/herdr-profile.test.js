const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const utils = require('../../static/js/profile-launcher-utils.js');
const {
    buildDirectConnectionData,
    herdrEditorPayload,
    herdrEditorState,
    herdrFellBack,
    requestsHerdrSession,
    sessionModeOf,
} = utils;

const editor = overrides => ({
    enabled: true, tmuxAvailable: true, saved: null, herdr: false, mode: 'tmux', startupMode: 'none',
    ...overrides,
});

test('saved session mode maps to exactly one choice', () => {
    assert.equal(sessionModeOf(null, true), 'tmux');
    assert.equal(sessionModeOf(null, false), 'shell');
    assert.equal(sessionModeOf({use_tmux: true}, false), 'tmux');
    assert.equal(sessionModeOf({use_tmux: false}, true), 'shell');
    assert.equal(sessionModeOf({herdr: true, use_herdr: true}, true), 'herdr');
    assert.equal(sessionModeOf({herdr: true, use_herdr: true, use_tmux: true}, false), 'tmux');
    assert.equal(sessionModeOf({use_herdr: 'true'}, false), 'shell');
});

test('Herdr session mode needs the host option and no startup commands', () => {
    assert.deepEqual(herdrEditorState(editor()), {
        visible: true, optionLocked: false, herdrLocked: true, reason: 'needsOption', mode: 'tmux',
    });
    assert.deepEqual(herdrEditorState(editor({herdr: true, mode: 'herdr'})), {
        visible: true, optionLocked: false, herdrLocked: false, reason: '', mode: 'herdr',
    });
    for (const startupMode of ['command_set', 'command', 'free_text']) {
        assert.deepEqual(herdrEditorState(editor({herdr: true, mode: 'herdr', startupMode})), {
            visible: true, optionLocked: false, herdrLocked: true, reason: 'noStartup', mode: 'shell',
        }, startupMode);
    }
    assert.equal(herdrEditorState(editor({herdr: false, mode: 'herdr'})).mode, 'shell');
    assert.equal(herdrEditorState(editor({tmuxAvailable: false, mode: 'tmux'})).mode, 'shell');
});

test('host editor stays as it is while the integration is off and the host has no Herdr values', () => {
    assert.equal(herdrEditorState(editor({enabled: false})).visible, false);
    assert.equal(herdrEditorState(editor({enabled: false, saved: {use_tmux: true}})).visible, false);
    assert.equal(herdrEditorPayload(editor({enabled: false, herdr: true, mode: 'herdr'})), null);
});

test('saved Herdr values stay visible and locked while the integration is off', () => {
    const saved = {herdr: true, use_herdr: true};
    assert.deepEqual(herdrEditorState(editor({enabled: false, saved, herdr: true, mode: 'herdr'})), {
        visible: true, optionLocked: true, herdrLocked: true, reason: '', mode: 'herdr',
    });
    assert.equal(herdrEditorState(editor({enabled: false, saved: {herdr: true}, herdr: true, mode: 'tmux'})).visible, true);
    // Keeping the locked choice writes nothing; choosing another mode replaces only the mode.
    assert.deepEqual(herdrEditorPayload(editor({enabled: false, saved, herdr: true, mode: 'herdr'})), {});
    assert.deepEqual(herdrEditorPayload(editor({enabled: false, saved, herdr: true, mode: 'tmux'})),
        {use_herdr: false, use_tmux: true});
    assert.deepEqual(herdrEditorPayload(editor({enabled: false, saved, herdr: true, mode: 'shell'})),
        {use_herdr: false, use_tmux: false});
});

test('host editor never writes Herdr together with tmux or without the option', () => {
    assert.deepEqual(herdrEditorPayload(editor()), {herdr: false, use_herdr: false, use_tmux: true});
    assert.deepEqual(herdrEditorPayload(editor({herdr: true, mode: 'herdr'})),
        {herdr: true, use_herdr: true, use_tmux: false});
    assert.deepEqual(herdrEditorPayload(editor({herdr: true, mode: 'shell'})),
        {herdr: true, use_herdr: false, use_tmux: false});
    assert.deepEqual(herdrEditorPayload(editor({herdr: false, mode: 'herdr'})),
        {herdr: false, use_herdr: false, use_tmux: false});
    assert.deepEqual(herdrEditorPayload(editor({herdr: true, mode: 'herdr', startupMode: 'free_text'})),
        {herdr: true, use_herdr: false, use_tmux: false});
    // Without tmux controls the stored tmux value is only touched when Herdr replaces it.
    assert.deepEqual(herdrEditorPayload(editor({tmuxAvailable: false, herdr: true, mode: 'shell'})),
        {herdr: true, use_herdr: false});
    assert.deepEqual(herdrEditorPayload(editor({tmuxAvailable: false, herdr: true, mode: 'herdr'})),
        {herdr: true, use_herdr: true, use_tmux: false});
});

test('a saved host asks for Herdr only with both options and never with tmux', () => {
    const base = {host: 'server.example', port: 22, username: 'alice', auth_type: 'key', key_id: 'key'};
    const context = {keys: [{id: 'key', usable: true}]};
    assert.equal(buildDirectConnectionData({...base, herdr: true, use_herdr: true}, context).use_herdr, true);
    for (const profile of [
        {...base}, {...base, herdr: true}, {...base, use_herdr: true},
        {...base, herdr: 'true', use_herdr: 'true'},
        {...base, herdr: true, use_herdr: true, use_tmux: true},
        {...base, herdr: true, use_herdr: true, startup_mode: 'free_text', startup_commands: 'pwd'},
    ]) {
        assert.equal(Object.hasOwn(buildDirectConnectionData(profile, context), 'use_herdr'), false, JSON.stringify(profile));
    }
});

test('the connection form asks for Herdr for a Herdr host or a Herdr reconnect', () => {
    const profile = {herdr: true, use_herdr: true};
    assert.equal(requestsHerdrSession({profile, connectionData: {startup_mode: 'none'}}), true);
    assert.equal(requestsHerdrSession({profile, connectionData: {}}), true);
    assert.equal(requestsHerdrSession({reconnect: true, connectionData: {}}), true);
    assert.equal(requestsHerdrSession({profile, connectionData: {use_tmux: true}}), false);
    assert.equal(requestsHerdrSession({profile, connectionData: {startup_mode: 'command_set'}}), false);
    assert.equal(requestsHerdrSession({profile: {herdr: true}, connectionData: {}}), false);
    assert.equal(requestsHerdrSession({profile: null, connectionData: {}}), false);
    assert.equal(requestsHerdrSession({connectionData: {}}), false);
});

test('a missing Herdr is reported only when the server allowed the mode and started a plain shell', () => {
    const profile = {herdr: true, use_herdr: true};
    assert.equal(herdrFellBack(profile, {herdr: true, use_herdr: false}), true);
    assert.equal(herdrFellBack(profile, {herdr: true}), true);
    assert.equal(herdrFellBack(profile, {herdr: true, use_herdr: true}), false);
    assert.equal(herdrFellBack(profile, {herdr: false, use_herdr: false}), false);
    assert.equal(herdrFellBack(profile, {herdr: true, use_herdr: false, use_tmux: true}), false);
    assert.equal(herdrFellBack({herdr: true}, {herdr: true, use_herdr: false}), false);
    assert.equal(herdrFellBack(null, {herdr: true, use_herdr: false}), false);
});

function editorDocument() {
    const elements = new Map();
    const getElementById = id => {
        if (!elements.has(id)) {
            const classes = new Set();
            elements.set(id, {
                id, value: '', checked: false, disabled: false, open: true, textContent: '', dataset: {default: 'true'},
                classList: {add: name => classes.add(name), remove: name => classes.delete(name), contains: name => classes.has(name)},
                reset() {}, focus() {},
            });
        }
        return elements.get(id);
    };
    return {getElementById};
}

function loadEditor({enabled, profile}) {
    const document = editorDocument();
    const context = {document, window: {ProfileLauncherUtils: utils, i18n: {t: key => `[${key}]`}}};
    vm.createContext(context);
    vm.runInContext(fs.readFileSync(path.join(__dirname, '../../static/js/profile-manager.js'), 'utf8'), context);
    const manager = context.window.ProfileManager;
    manager.renderEditorSelects = () => {};
    manager.setInlineKeyPanelExpanded = () => {};
    manager.updateEditorVisibility = () => {};
    manager.renderManagementList = () => {};
    manager.herdrEnabled = enabled;
    manager.profiles = profile ? [profile] : [];
    manager.openEditor(profile?.id);
    const field = id => document.getElementById(id);
    const hidden = id => field(id).classList.contains('hidden');
    const mode = () => ['Shell', 'Tmux', 'Herdr'].filter(name => field(`profileEditorMode${name}`).checked);
    return {manager, field, hidden, mode};
}

test('host editor loads saved Herdr values and locks the mode until its conditions hold', () => {
    const {manager, field, hidden, mode} = loadEditor({enabled: true,
        profile: {id: 'saved', herdr: true, use_herdr: true, use_tmux: false, startup_mode: 'none'}});
    assert.equal(hidden('profileEditorHerdrBlock'), false);
    assert.equal(hidden('profileEditorTmuxGroup'), true);
    assert.equal(hidden('profileEditorHerdrDisabled'), true);
    assert.equal(field('profileEditorHerdr').checked, true);
    assert.equal(field('profileEditorHerdr').disabled, false);
    assert.deepEqual(mode(), ['Herdr']);
    assert.equal(field('profileEditorModeHerdr').disabled, false);
    assert.equal(hidden('profileEditorHerdrModeReason'), true);
    assert.deepEqual({...manager.herdrEditorPayload()}, {herdr: true, use_herdr: true, use_tmux: false});

    field('profileEditorPostConnectMode').value = 'command_set';
    manager.syncHerdrEditor();
    assert.deepEqual(mode(), ['Shell']);
    assert.equal(field('profileEditorModeHerdr').disabled, true);
    assert.equal(field('profileEditorHerdrModeReason').textContent, '[herdr.sessionModeNoStartup]');
    assert.equal(hidden('profileEditorHerdrModeReason'), false);
    assert.deepEqual({...manager.herdrEditorPayload()}, {herdr: true, use_herdr: false, use_tmux: false});

    field('profileEditorPostConnectMode').value = 'none';
    field('profileEditorHerdr').checked = false;
    manager.syncHerdrEditor();
    assert.equal(field('profileEditorModeHerdr').disabled, true);
    assert.equal(field('profileEditorHerdrModeReason').textContent, '[herdr.sessionModeNeedsOption]');
});

test('host editor offers the choice for a new host with the deployment default', () => {
    const {field, hidden, mode} = loadEditor({enabled: true});
    assert.equal(hidden('profileEditorHerdrBlock'), false);
    assert.equal(field('profileEditorHerdr').checked, false);
    assert.deepEqual(mode(), ['Tmux']);
    assert.equal(field('profileEditorModeHerdr').disabled, true);
});

test('host editor keeps the tmux checkbox alone while the integration is off', () => {
    const {manager, field, hidden} = loadEditor({enabled: false, profile: {id: 'saved', use_tmux: true}});
    assert.equal(hidden('profileEditorHerdrBlock'), true);
    assert.equal(hidden('profileEditorTmuxGroup'), false);
    assert.equal(field('profileEditorUseTmux').checked, true);
    assert.equal(manager.herdrEditorPayload(), null);
});

test('host editor shows locked Herdr values with the reason while the integration is off', () => {
    const {manager, field, hidden, mode} = loadEditor({enabled: false,
        profile: {id: 'saved', herdr: true, use_herdr: true}});
    assert.equal(hidden('profileEditorHerdrBlock'), false);
    assert.equal(hidden('profileEditorHerdrDisabled'), false);
    assert.equal(field('profileEditorHerdr').checked, true);
    assert.equal(field('profileEditorHerdr').disabled, true);
    assert.equal(field('profileEditorModeHerdr').disabled, true);
    assert.deepEqual(mode(), ['Herdr']);
    assert.equal(hidden('profileEditorHerdrModeReason'), true);
    assert.deepEqual({...manager.herdrEditorPayload()}, {});
});

function sessionManager(session) {
    const sent = [];
    const fields = new Map();
    const context = {document: {body: {dataset: {}}, getElementById(id) {
        if (!fields.has(id)) fields.set(id, {value: '', checked: false, dispatchEvent() {}, focus() {},
            classList: {add() {}, remove() {}, toggle() {}}});
        return fields.get(id);
    }}, Event: function Event() {}, window: {
        socket: {emit: (event, payload) => sent.push({event, payload})},
        showNotification() {}, prepareSessionReconnectJump: () => ({}), clearConnectionProfileState() {},
    }, confirm: () => true, setTimeout: fn => fn()};
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../../static/js/session-manager.js'), 'utf8')
        + '\n globalThis.manager = SessionManager;', context);
    const manager = context.manager;
    manager.getDisplayLabel = () => 'test';
    manager.closeSession = () => {};
    manager.removeSessionUI = () => {};
    manager.sessions.test = {host: 'host.example', port: 22, username: 'test', connected: true,
        profileId: 'saved', ...session};
    return {manager, sent};
}

test('key reconnect of a Herdr session asks for the Herdr mode again', () => {
    const {manager, sent} = sessionManager({keyId: 'key', authType: 'key', herdr: true, useHerdr: true});
    manager.requestReconnect('test');
    assert.equal(sent.length, 1);
    assert.equal(sent[0].payload.use_herdr, true);
    assert.notEqual(sent[0].payload.use_tmux, true);
    assert.equal(sent[0].payload.profile_id, 'saved');
});

test('reconnect of other sessions never asks for Herdr', () => {
    for (const session of [{}, {herdr: true}, {useTmux: true, tmuxSessionName: 'main', useHerdr: true}]) {
        const {manager, sent} = sessionManager({keyId: 'key', authType: 'key', ...session});
        manager.requestReconnect('test');
        assert.equal(Object.hasOwn(sent[0].payload, 'use_herdr'), false, JSON.stringify(session));
    }
});

test('password reconnect of a Herdr session carries the mode into the connection form', () => {
    const {manager, sent} = sessionManager({authType: 'password', herdr: true, useHerdr: true});
    manager.requestReconnect('test');
    assert.equal(sent.length, 0);
    assert.equal(manager.pendingReconnectHerdr, true);
    assert.equal(manager.pendingReconnectProfileId, 'saved');
    const plain = sessionManager({authType: 'password'});
    plain.manager.requestReconnect('test');
    assert.equal(plain.manager.pendingReconnectHerdr, false);
});
