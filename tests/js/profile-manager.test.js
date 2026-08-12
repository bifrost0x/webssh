const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

function loadProfileManager() {
    const source = fs.readFileSync(path.join(
        __dirname,
        '../../static/js/profile-manager.js',
    ), 'utf8');
    const context = { window: {} };

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
