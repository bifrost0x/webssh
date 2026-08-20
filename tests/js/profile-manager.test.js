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

test('failed key replacement preserves private-key draft for retry', () => {
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

    assert.equal(emitted.event, 'replace_key');
    assert.equal(emitted.payload.key_id, 'key-1');
    assert.equal(emitted.payload.key_content, 'private-key-draft');
    assert.equal(manager.replacingKeyId, 'key-1');
    assert.equal(manager.replacementKeyContent, 'private-key-draft');
    assert.equal(manager.keyReplacePending, false);
});

test('successful key replacement clears draft and merges safe summary', () => {
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
            profiles: [{id: 'profile-1', name: 'API', group: 'Homelab', sort_order: 0}],
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
            profiles: [{id: 'profile-1', name: 'API', group: 'Current'}],
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
                profiles: manager.profiles,
            });
            return;
        }
        acknowledge({
            success: true,
            requires_confirmation: false,
            profiles: [{id: 'profile-1', name: 'DB', group: 'Apps', sort_order: 0}],
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
