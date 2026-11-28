const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

function loadProfileManager(contextOverrides = {}) {
    const source = fs.readFileSync(path.join(
        __dirname,
        '../../static/js/profile-manager.js',
    ), 'utf8');
    const context = { window: {}, ...contextOverrides };

    vm.createContext(context);
    vm.runInContext(source, context);

    const manager = context.window.ProfileManager;
    manager.__testWindow = context.window;
    manager.setKeys = function setKeys(keys) {
        this.keys = keys;
    };
    return manager;
}

test('leaving a host editor protects dirty edits and ignores a stale discard decision', async () => {
    let snapshot = 'draft';
    let answer = false;
    let confirmCount = 0;
    let left = 0;
    const manager = loadProfileManager({document: {
        getElementById: () => ({classList: {contains: () => true}}),
        querySelectorAll: () => [],
    }});
    manager.editorBaseline = 'saved';
    manager.editingProfileId = 'host';
    manager.editorSnapshot = () => snapshot;
    manager.showManagementList = () => { left += 1; };
    manager.__testWindow.CommandSetManager = {confirmDialog: async () => {confirmCount += 1; return answer;}};
    await manager.requestManagementList();
    assert.equal(left, 0);
    answer = true;
    await manager.requestManagementList();
    assert.equal(left, 1);
    snapshot = 'saved';
    await manager.requestManagementList();
    assert.equal(left, 2);
    assert.equal(confirmCount, 2);
    snapshot = 'draft';
    let resolve;
    manager.__testWindow.CommandSetManager.confirmDialog = () => new Promise(done => {resolve = done;});
    const pending = manager.requestManagementList();
    snapshot = 'newer draft';
    resolve(true);
    await pending;
    assert.equal(left, 2);
});

test('partial key mutation replies preserve transient usability', () => {
    const manager = loadProfileManager();
    manager.keys = [{
        id: 'key-1',
        name: 'Original name',
        type: 'Ed25519',
        usable: true,
    }];

    manager.upsertKeySummary({
        id: 'key-1',
        name: 'Renamed key',
        type: 'Ed25519',
    });

    assert.equal(manager.keys[0].name, 'Renamed key');
    assert.equal(manager.keys[0].usable, true);
});

test('profile upsert replaces fields cleared by the authoritative server record', () => {
    const manager = loadProfileManager();
    manager.renderProfileSelect = () => {};
    manager.renderManagementList = () => {};
    manager.refreshEmptyPanes = () => {};
    manager.profiles = [{
        id: 'profile-1',
        name: 'Production API',
        group: 'Production',
        favorite: true,
    }];

    manager.upsertProfile({
        id: 'profile-1',
        name: 'Production API',
    });

    assert.deepEqual(manager.profiles, [{
        id: 'profile-1',
        name: 'Production API',
    }]);
    assert.equal('group' in manager.profiles[0], false);
    assert.equal('favorite' in manager.profiles[0], false);
});

test('profile refresh updates existing session icons through the lexical session manager', () => {
    const sessions = {sessions: {existing: {profileId: 'profile-1'}}};
    let refreshed;
    const manager = loadProfileManager({SessionManager: sessions, window: {
        HostPlatform: {refreshSessionIcons(sessionManager, profiles) {refreshed = {sessionManager, profiles};}},
    }});
    manager.renderProfileSelect = () => {};
    manager.renderManagementList = () => {};
    manager.refreshEmptyPanes = () => {};
    manager.setProfiles([{id: 'profile-1', platform_icon: 'debian'}]);
    assert.equal(refreshed.sessionManager, sessions);
    assert.equal(refreshed.profiles[0].platform_icon, 'debian');
});

test('failed key replacement preserves private-key draft for retry', async () => {
    const manager = loadProfileManager();
    manager.keys = [{
        id: 'key-1',
        name: 'Production key',
        key_type: 'Ed25519',
        usable: true,
    }];
    manager.replacingKeyId = 'key-1';
    manager.renderKeysList = () => {};
    manager.t = (_key, fallback) => fallback;
    let emitted = null;
    manager.__testWindow.socket = {
        emit(event, payload, acknowledgement) {
            emitted = {event, payload};
            acknowledgement({success: false, error: 'Replacement rejected'});
        },
    };

    manager.submitKeyReplacement('key-1', 'private-key-draft');
    await new Promise(resolve => setImmediate(resolve));

    assert.equal(emitted.event, 'replace_key');
    assert.equal(emitted.payload.key_id, 'key-1');
    assert.equal(emitted.payload.key_content, 'private-key-draft');
    assert.equal(manager.replacingKeyId, 'key-1');
    assert.equal(manager.replacementKeyContent, 'private-key-draft');
    assert.equal(manager.keyReplacePending, false);
});

test('successful key replacement clears draft and merges safe summary', async () => {
    const manager = loadProfileManager();
    manager.keys = [{
        id: 'key-1',
        name: 'Production key',
        key_type: 'Ed25519',
        usable: true,
    }];
    manager.replacingKeyId = 'key-1';
    manager.renderKeysList = () => {};
    manager.t = (_key, fallback) => fallback;
    manager.__testWindow.socket = {
        emit(_event, _payload, acknowledgement) {
            acknowledgement({
                success: true,
                key: {
                    id: 'key-1',
                    name: 'Production key',
                    key_type: 'Ed25519',
                    usable: true,
                },
            });
        },
    };

    manager.submitKeyReplacement('key-1', 'replacement-private-key');
    await new Promise(resolve => setImmediate(resolve));

    assert.equal(manager.replacingKeyId, null);
    assert.equal(manager.replacementKeyContent, '');
    assert.equal(manager.keyReplacePending, false);
    assert.equal(manager.keys[0].usable, true);
});

test('favorite acknowledgement replaces cleared organization fields', () => {
    const manager = loadProfileManager();
    manager.profiles = [{
        id: 'profile-1',
        name: 'API',
        favorite: true,
        group: 'Production',
        tailscale_authorized: true,
    }];
    manager.renderManagementList = () => {};
    manager.refreshEmptyPanes = () => {};
    manager.renderProfileSelect = () => {};
    manager.organizationPending = new Set();
    manager.t = (_key, fallback) => fallback;
    manager.profilesLoaded = true;
    manager.keys = [];
    manager.editingProfileId = null;
    manager.inlineKeyUploadPending = false;
    manager.keyRenamePending = false;
    manager.toggleFavorite('profile-1', acknowledgement => {
        acknowledgement({
            success: true,
            profile: {id: 'profile-1', name: 'API', group: 'Production'},
        });
    });

    assert.equal(manager.profiles[0].favorite, undefined);
    assert.equal(manager.profiles[0].tailscale_authorized, true);
});

test('favorite acknowledgement adopts fresh tailscale authorization', () => {
    const manager = loadProfileManager();
    manager.profiles = [{
        id: 'profile-1',
        name: 'Tailnet API',
        favorite: false,
        tailscale_authorized: true,
    }];
    manager.renderManagementList = () => {};
    manager.refreshEmptyPanes = () => {};
    manager.renderProfileSelect = () => {};
    manager.organizationPending = new Set();
    manager.t = (_key, fallback) => fallback;
    manager.toggleFavorite('profile-1', acknowledgement => {
        acknowledgement({
            success: true,
            profile: {
                id: 'profile-1',
                name: 'Tailnet API',
                favorite: true,
                tailscale_authorized: false,
            },
        });
    });

    assert.equal(manager.profiles[0].favorite, true);
    assert.equal(manager.profiles[0].tailscale_authorized, false);
});

test('collapsed group state toggles for the session but search keeps matches visible', () => {
    const manager = loadProfileManager();
    manager.collapsedGroups = new Set();
    manager.profileSearchQuery = '';
    manager.renderManagementList = () => {};

    assert.equal(manager.isGroupCollapsed('group:production'), false);
    manager.toggleGroupCollapsed('group:production');
    assert.equal(manager.isGroupCollapsed('group:production'), true);

    manager.profileSearchQuery = 'api';
    assert.equal(manager.isGroupCollapsed('group:production'), false);

    manager.profileSearchQuery = '';
    manager.toggleGroupCollapsed('group:production');
    assert.equal(manager.isGroupCollapsed('group:production'), false);
});

test('collapse all records every rendered profile section', () => {
    const manager = loadProfileManager();
    manager.__testWindow.ProfileLauncherUtils = require(
        '../../static/js/profile-launcher-utils.js'
    );
    manager.profiles = [
        {id: 'favorite', name: 'Favorite', group: 'Production', favorite: true},
        {id: 'grouped', name: 'Grouped', group: 'Production'},
        {id: 'ungrouped', name: 'Ungrouped'},
    ];
    manager.profileSearchQuery = '';
    manager.collapsedGroups = new Set();
    let renders = 0;
    manager.renderManagementList = () => { renders += 1; };

    assert.equal(manager.collapseAllGroups(), true);
    assert.deepEqual([...manager.collapsedGroups].sort(), [
        'favorites',
        'group:production',
        'ungrouped',
    ]);
    assert.equal(renders, 1);
});

test('collapse all stays inactive while search results are expanded', () => {
    const manager = loadProfileManager();
    manager.__testWindow.ProfileLauncherUtils = require(
        '../../static/js/profile-launcher-utils.js'
    );
    manager.profiles = [{id: 'profile-1', name: 'API', group: 'Production'}];
    manager.profileSearchQuery = 'api';
    manager.collapsedGroups = new Set();
    manager.renderManagementList = () => {
        throw new Error('search must not collapse or rerender groups');
    };

    assert.equal(manager.collapseAllGroups(), false);
    assert.deepEqual([...manager.collapsedGroups], []);
});

test('opening Hosts focuses the saved connection search', () => {
    let focused = null;
    const modal = {
        classList: {contains() { return false; }},
        querySelector(selector) {
            if (selector === '#profileSearchInput') {
                return {focus() { focused = 'search'; }};
            }
            if (selector === '[data-connection-asset="hosts"]') {
                return {focus() { focused = 'hosts'; }};
            }
            return null;
        },
    };
    const manager = loadProfileManager({
        document: {
            getElementById(id) {
                return id === 'profileManagementModal' ? modal : null;
            },
        },
    });
    manager.showManagementList = () => {};
    manager.loadProfiles = () => {};
    manager.loadKeys = () => {};
    manager.__testWindow.ModalManager = {open() {}};

    manager.openManagement();

    assert.equal(focused, 'search');
});

test('moving a profile applies only the authoritative successful response', () => {
    const manager = loadProfileManager();
    manager.profiles = [{
        id: 'profile-1',
        name: 'API',
        group: 'Production',
        tailscale_authorized: true,
    }];
    manager.organizationPending = new Set();
    manager.renderManagementList = () => {};
    manager.renderProfileSelect = () => {};
    manager.refreshEmptyPanes = () => {};
    manager.t = (_key, fallback) => fallback;

    const move = {
        profileId: 'profile-1',
        expectedSourceGroup: 'Production',
        targetGroup: 'Homelab',
        targetIndex: 0,
    };
    const started = manager.requestProfileMove(move, (payload, acknowledge) => {
        assert.equal(manager.profiles[0].group, 'Production');
        assert.deepEqual(JSON.parse(JSON.stringify(payload)), {
            profile_id: 'profile-1',
            expected_source_group: 'Production',
            target_group: 'Homelab',
            target_index: 0,
            confirm_source_group_removal: false,
        });
        acknowledge({
            success: true,
            organization: [{
                id: 'profile-1', group: 'Homelab', sort_order: 0,
            }],
        });
    });

    assert.equal(started, true);
    assert.equal(manager.profiles[0].group, 'Homelab');
    assert.equal(manager.profiles[0].tailscale_authorized, true);
    assert.equal(manager.organizationPending.has('profile-1'), false);
});

test('move failure keeps the original state and adopts authoritative stale state', () => {
    const manager = loadProfileManager();
    manager.profiles = [{id: 'profile-1', name: 'API', group: 'Production'}];
    manager.organizationPending = new Set();
    manager.renderManagementList = () => {};
    manager.renderProfileSelect = () => {};
    manager.refreshEmptyPanes = () => {};
    manager.t = (_key, fallback) => fallback;

    assert.equal(manager.requestProfileMove({
        profileId: 'profile-1',
        expectedSourceGroup: 'Production',
        targetGroup: '',
        targetIndex: 0,
    }, (_payload, acknowledge) => {
        acknowledge({
            success: false,
            error: 'Profile group changed; retry move',
            organization: [{id: 'profile-1', group: 'Current', sort_order: 0}],
        });
    }), true);
    assert.equal(manager.profiles[0].group, 'Current');
    assert.equal(manager.organizationPending.has('profile-1'), false);
});

test('group removal acknowledgement opens confirmation and retries explicitly', () => {
    const manager = loadProfileManager();
    manager.profiles = [{id: 'profile-1', name: 'DB', group: 'Databases'}];
    manager.organizationPending = new Set();
    manager.renderManagementList = () => {};
    manager.renderProfileSelect = () => {};
    manager.refreshEmptyPanes = () => {};
    manager.openProfileMoveConfirmation = () => {};
    manager.closeProfileMoveConfirmation = () => {};
    manager.t = (_key, fallback) => fallback;

    const payloads = [];
    const emit = (payload, acknowledge) => {
        payloads.push(payload);
        if (payloads.length === 1) {
            acknowledge({
                success: false,
                requires_confirmation: true,
                profile_name: 'DB',
                source_group: 'Databases',
            });
            return;
        }
        acknowledge({
            success: true,
            requires_confirmation: false,
            organization: [{id: 'profile-1', group: 'Apps', sort_order: 0}],
        });
    };
    const move = {
        profileId: 'profile-1',
        expectedSourceGroup: 'Databases',
        targetGroup: 'Apps',
        targetIndex: 0,
    };

    assert.equal(manager.requestProfileMove(move, emit), true);
    assert.equal(manager.pendingProfileMove.move, move);
    assert.equal(manager.organizationPending.has('profile-1'), false);
    assert.equal(manager.confirmPendingProfileMove(), true);
    assert.equal(payloads[1].confirm_source_group_removal, true);
    assert.equal(manager.profiles[0].group, 'Apps');
    assert.equal(manager.pendingProfileMove, null);
});

test('duplicate profile names are localized and remain within storage limit', () => {
    const manager = loadProfileManager();
    manager.t = key => key === 'profiles.copyNameSuffix' ? ' (Kopie)' : key;

    assert.equal(manager.duplicateProfileName('Production'), 'Production (Kopie)');
    const bounded = manager.duplicateProfileName('x'.repeat(128));
    assert.equal(bounded.length, 128);
    assert.equal(bounded.endsWith(' (Kopie)'), true);
});

test('compact profile inspector retains persistence while advanced options start collapsed', () => {
    const utils = require('../../static/js/profile-launcher-utils.js');
    const cases = [
        {label: 'new host with persistence default', defaultTmux: true, checked: true, open: false},
        {label: 'new host without persistence default', defaultTmux: false, checked: false, open: false},
        {label: 'saved opt-out overrides deployment default', defaultTmux: true,
            profile: {id: 'saved', use_tmux: false}, checked: false, open: false},
        {label: 'duplicate keeps saved persistence', defaultTmux: false,
            profile: {id: 'saved', use_tmux: true}, duplicate: true, checked: true, open: false},
        {label: 'startup commands still reveal advanced settings', defaultTmux: false,
            profile: {id: 'saved', startup_mode: 'free_text', startup_commands: 'pwd'},
            checked: false, open: false},
        {label: 'deployment without tmux controls', tmuxEnabled: false, open: false},
    ];
    for (const scenario of cases) {
        const elements = new Map();
        const document = {getElementById(id) {
            if (id === 'profileEditorUseTmux' && scenario.tmuxEnabled === false) return null;
            if (!elements.has(id)) elements.set(id, {
                value: '', checked: false, open: true,
                dataset: {default: String(scenario.defaultTmux)},
                classList: {add() {}, remove() {}, contains() {return false;}}, reset() {}, focus() {},
            });
            return elements.get(id);
        }};
        const manager = loadProfileManager({document, window: {ProfileLauncherUtils: utils}});
        manager.renderEditorSelects = () => {};
        manager.setInlineKeyPanelExpanded = () => {};
        manager.updateEditorVisibility = () => {};
        manager.renderManagementList = () => {};
        manager.profiles = scenario.profile ? [scenario.profile] : [];

        manager.openEditor(scenario.profile?.id, {duplicate: scenario.duplicate});

        assert.equal(document.getElementById('profileAdvancedSettingsCard').open,
            scenario.open, scenario.label);
        if (scenario.tmuxEnabled !== false) {
            assert.equal(document.getElementById('profileEditorUseTmux').checked,
                scenario.checked, scenario.label);
        }
    }
});

test('the host editor sends one save at a time and adopts a host created while the form changed', async () => {
    const fields = {};
    const field = (value = '') => ({value, checked: false, dataset: {}, classList: {contains: () => false}});
    for (const id of ['profileEditorPostConnectMode', 'profileEditorName', 'profileEditorGroup', 'profileEditorHost',
        'profileEditorPort', 'profileEditorUsername', 'profileEditorAuthType', 'profileEditorKeySelect',
        'profileEditorJumpHostSelect', 'profileEditorPlatformIcon', 'profileEditorRole', 'profileEditorView']) fields[id] = field();
    fields.profileEditorPostConnectMode.value = 'none';
    fields.profileEditorAuthType.value = 'password';
    fields.profileEditorName.value = 'Once';
    const buttons = [{disabled: false, setAttribute() {}, removeAttribute() {}}, {disabled: false, setAttribute() {}, removeAttribute() {}}];
    const sent = [];
    const manager = loadProfileManager({document: {getElementById: id => fields[id] || null, querySelectorAll: () => buttons}});
    manager.__testWindow.socket = {emit: (event, payload, ack) => sent.push([event, payload, ack])};
    let snapshot = 'before';
    manager.editorSnapshot = () => snapshot;
    manager.herdrEditorPayload = () => null;
    manager.profiles = [];
    manager.editingProfileId = null;

    await manager.saveFromEditor();
    await manager.saveFromEditor({connect: true});
    assert.equal(sent.length, 1, 'a second click while the save is on its way sends nothing');
    assert.deepEqual(buttons.map(button => button.disabled), [true, true]);

    // Another render changed the form before the answer arrived: the
    // editor stays open, but the next save updates the created host.
    snapshot = 'after';
    await sent[0][2]({success: true, profile: {id: 'created-1', name: 'Once'}});
    assert.deepEqual(buttons.map(button => button.disabled), [false, false]);
    assert.equal(manager.editingProfileId, 'created-1');
    await manager.saveFromEditor();
    assert.equal(sent.length, 2);
    assert.equal(sent[1][1].id, 'created-1');
});

test('a new host with a saved password is confirmed before anything is saved', async () => {
    const fields = {};
    const field = (value = '') => ({value, checked: false, dataset: {}, classList: {contains: () => false}});
    for (const id of ['profileEditorPostConnectMode', 'profileEditorName', 'profileEditorGroup', 'profileEditorHost',
        'profileEditorPort', 'profileEditorUsername', 'profileEditorAuthType', 'profileEditorKeySelect',
        'profileEditorJumpHostSelect', 'profileEditorPlatformIcon', 'profileEditorRole', 'profileEditorView',
        'profileEditorCredential']) fields[id] = field();
    fields.profileEditorPostConnectMode.value = 'none';
    fields.profileEditorAuthType.value = 'password';
    fields.profileEditorName.value = 'Bound';
    fields.profileEditorHost.value = 'bound.example';
    fields.profileEditorUsername.value = 'u';
    fields.profileEditorCredential.value = 'saved-1';
    const calls = [];
    const manager = loadProfileManager({document: {getElementById: id => fields[id] || null, querySelectorAll: () => []}});
    const win = manager.__testWindow;
    win.socket = {emit: (event, payload, ack) => { calls.push(['emit', event]); ack?.({success: true, profile: {id: 'p1'}}); }};
    manager.editorSnapshot = () => 'snapshot';
    manager.herdrEditorPayload = () => null;
    manager.profiles = [];
    manager.editingProfileId = null;
    const cancelled = Object.assign(new Error('Cancelled'), {name: 'AbortError'});

    // Without the one-step create (Python): the confirmation comes first,
    // and cancelling it saves nothing.
    win.NativeCredentials = {
        supports: () => false,
        authorizeTarget: async id => { calls.push(['authorize', id]); throw cancelled; },
        mutate: async method => { calls.push(['mutate', method]); return {}; },
    };
    await manager.saveFromEditor();
    assert.deepEqual(calls, [['authorize', 'saved-1']]);
    assert.equal(manager.profileSavePending, false);

    calls.length = 0;
    win.NativeCredentials.authorizeTarget = async id => { calls.push(['authorize', id]); };
    await manager.saveFromEditor();
    assert.deepEqual(calls.slice(0, 2), [['authorize', 'saved-1'], ['emit', 'save_profile']]);

    // With it (Go): host and assignment in one request; no save_profile.
    await new Promise(resolve => setImmediate(resolve));
    manager.editingProfileId = null;
    calls.length = 0;
    win.NativeCredentials.supports = feature => feature === 'assign_on_create';
    win.NativeCredentials.mutate = async (method, payload) => {
        calls.push(['mutate', method, payload.credential_id, Object.hasOwn(payload, 'password')]);
        throw cancelled;
    };
    await manager.saveFromEditor();
    assert.deepEqual(calls, [['mutate', 'create_for_resource', 'saved-1', false]]);
    assert.equal(manager.profileSavePending, false);
});

test('the host editor loads and saves the role override', async () => {
    const fields = {};
    const field = (value = '') => ({value, checked: false, dataset: {}, classList: {contains: () => false}});
    for (const id of ['profileEditorPostConnectMode', 'profileEditorName', 'profileEditorGroup', 'profileEditorHost',
        'profileEditorPort', 'profileEditorUsername', 'profileEditorAuthType', 'profileEditorKeySelect',
        'profileEditorJumpHostSelect', 'profileEditorPlatformIcon']) fields[id] = field();
    fields.profileEditorPostConnectMode.value = 'none';
    fields.profileEditorPort.value = '22';
    fields.profileEditorAuthType.value = 'password';
    const roles = new Set(['auto', 'backup', 'server']);
    let stored = 'auto';
    fields.profileEditorRole = {
        get value() { return stored; },
        set value(next) { stored = roles.has(next) ? next : ''; },
    };
    const sent = [];
    const manager = loadProfileManager({document: {getElementById: id => fields[id] || null}});
    // Answered at once: a save still on its way locks the next one.
    manager.__testWindow.socket = {emit: (event, payload, ack) => {
        sent.push([event, payload]);
        ack?.({success: false, error: 'not stored in this test'});
    }};
    manager.editorSnapshot = () => 'snapshot';
    manager.herdrEditorPayload = () => null;
    manager.profiles = [];

    fields.profileEditorRole.value = 'backup';
    await manager.saveFromEditor();
    assert.equal(sent[0][0], 'save_profile');
    assert.equal(sent[0][1].role_override, 'backup');

    fields.profileEditorRole.value = 'auto';
    await manager.saveFromEditor();
    assert.equal(sent[1][1].role_override, 'auto');
});
