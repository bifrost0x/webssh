const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function api() {
    if (!fs.existsSync('static/js/host-context.js')) return {};
    const context = {module: {exports: {}}, Map, structuredClone};
    vm.runInNewContext(fs.readFileSync('static/js/host-context.js', 'utf8'), context);
    return context.module.exports;
}

test('connection context keeps the explicitly selected profile and drops binding after target edits', () => {
    const context = {window: {}};
    vm.runInNewContext(fs.readFileSync('static/js/profile-manager.js', 'utf8'), context);
    const profiles = context.window.ProfileManager;
    profiles.profiles = [{id: 'one', host: 'example.com', port: 22, username: 'deploy'},
        {id: 'two', host: 'example.com', port: 22, username: 'deploy'}];
    const endpoint = {host: 'example.com', port: 22, username: 'deploy'};
    assert.equal(profiles.connectionProfileId(endpoint), null);
    profiles.selectedProfileId = 'two';
    assert.equal(profiles.connectionProfileId(endpoint), 'two');
    assert.equal(profiles.connectionProfileId({...endpoint, username: 'root'}), null);
    assert.equal(profiles.connectionProfileId({...endpoint, proxy_jump: {jump_host_id: 'j'}}), null);
});

test('direct saved-profile launcher carries its explicit stable identity', () => {
    const {createConnectionLauncher} = require('../../static/js/connection-launcher.js');
    let payload;
    const launch = createConnectionLauncher({getProfile: () => ({id: 'exact-profile', host: 'example.com', port: 22,
        username: 'deploy', auth_type: 'key', key_id: 'key', startup_mode: 'none'}),
    getContext: () => ({keys: [{id: 'key', usable: true}]}), getDefaultPaneIndex: () => 0,
    isBusy: () => false, startConnection: data => { payload = data; return true; },
    openReview() {}, notify() {}, refreshProfiles() {}});
    assert.equal(launch.launch('exact-profile'), 'connect');
    assert.equal(payload.profile_id, 'exact-profile');
});

test('late loads cannot replace another profile and unsaved drafts survive switching', async () => {
    const pending = new Map();
    const model = api().createController({request: id => new Promise(resolve => pending.set(id, resolve))});
    const first = model.open('one');
    const second = model.open('two');
    pending.get('two')({revision: 1, notes: 'two', directories: [], command_sets: []});
    await second;
    model.update({notes: 'draft two'});
    pending.get('one')({revision: 1, notes: 'one', directories: [], command_sets: []});
    await first;
    assert.equal(model.state.profileId, 'two');
    assert.equal(model.state.content.notes, 'draft two');
    await model.open('two');
    assert.equal(model.state.content.notes, 'draft two');
});

test('save conflicts keep local content and original revision', async () => {
    const model = api().createController({request: async (_id, body) => {
        if (body) throw Object.assign(new Error(), {code: 'conflict'});
        return {revision: 2, notes: 'saved', directories: [], command_sets: []};
    }});
    await model.open('one');
    model.update({notes: 'local draft'});
    assert.equal(await model.save(), false);
    assert.equal(model.state.content.notes, 'local draft');
    assert.equal(model.state.content.revision, 2);
    assert.equal(model.state.error, 'conflict');
});

test('unload protection includes hidden drafts and clears only after save or explicit discard', async () => {
    let finish;
    const model = api().createController({request: async (id, body) => body
        ? new Promise(resolve => { finish = () => resolve({...body, revision: 2}); })
        : {revision: 1, notes: id, directories: [], command_sets: []}});
    await model.open('one');
    assert.equal(model.hasUnsaved(), false);
    model.update({notes: 'keep this'});
    await model.open('two');
    assert.equal(model.hasUnsaved(), true);
    await model.open('one');
    const saving = model.save();
    await model.open(null);
    assert.equal(model.hasUnsaved(), true);
    finish();
    await saving;
    assert.equal(model.hasUnsaved(), false);
    await model.open('two');
    model.update({notes: 'discard this'});
    assert.equal(model.hasUnsaved(), true);
    await model.open('two', null, true);
    assert.equal(model.hasUnsaved(), false);
});

test('stale actions and ad-hoc sessions cannot launch assigned commands or directories', async () => {
    let active = {id: 'a', profileId: 'one', connected: true};
    const calls = [];
    const model = api().createController({request: async () => ({revision: 1, notes: '', directories: ['/logs'], command_sets: ['set']}),
        getActiveSession: () => active, directory: (...args) => calls.push(args), commandSet: (...args) => calls.push(args)});
    await model.open('one', 'a');
    assert.equal(await model.directory('/logs'), true);
    active = {id: 'b', profileId: 'one', connected: true};
    assert.equal(await model.commandSet('set'), false);
    active = {id: 'a', profileId: null, connected: true};
    assert.equal(await model.directory('/logs'), false);
    assert.equal(calls.length, 1);
});

test('a save completing after more edits preserves the newer local draft', async () => {
    let finish;
    const model = api().createController({request: async (_id, body) => body
        ? new Promise(resolve => {finish = resolve;})
        : {revision: 1, notes: '', directories: [], command_sets: []}});
    await model.open('one');
    model.update({notes: 'first'});
    const saving = model.save();
    model.update({notes: 'second'});
    finish({revision: 2, notes: 'first', directories: [], command_sets: []});
    await saving;
    assert.equal(model.state.content.notes, 'second');
    assert.equal(model.state.content.revision, 2);
    assert.equal(model.state.dirty, true);
});

test('an in-flight directory action remains bound to its original open context', async () => {
    let active = {id: 'a', profileId: 'one', connected: true};
    let validate;
    const model = api().createController({request: async () => ({revision: 1, notes: '', directories: ['/logs'], command_sets: []}),
        getActiveSession: () => active, directory: async (_id, _path, valid) => { validate = valid; }});
    await model.open('one', 'a');
    await model.directory('/logs');
    active = {id: 'b', profileId: 'one', connected: true};
    await model.open('one', 'b');
    assert.equal(validate(), false);
});

test('pending saves and their completion remain scoped to their host', async () => {
    const pending = new Map();
    let renders = 0;
    const model = api().createController({
        request: async (id, body) => body
            ? new Promise(resolve => pending.set(id, () => resolve({...body, revision: 2})))
            : {revision: 1, notes: id, directories: [], command_sets: []},
        changed: () => { renders += 1; },
    });
    await model.open('one');
    model.update({notes: 'first host draft'});
    const firstSave = model.save();
    await model.open('one');
    assert.equal(model.state.saving, true);
    assert.equal(await model.save(), false);
    await model.open('two');
    assert.equal(model.state.saving, false);
    model.update({notes: 'second host draft'});
    const secondSave = model.save();
    assert.equal(model.state.saving, true);
    const beforeCompletion = renders;
    pending.get('one')();
    await firstSave;
    assert.equal(model.state.saving, true);
    assert.equal(model.state.content.notes, 'second host draft');
    assert.equal(renders, beforeCompletion);
    pending.get('two')();
    await secondSave;
    assert.equal(model.state.saving, false);
    assert.equal(model.state.dirty, false);
    await model.open('one');
    assert.equal(model.state.content.notes, 'first host draft');
    assert.equal(model.state.dirty, false);
});

test('a failed background save keeps its own draft and error without disturbing another host', async () => {
    let fail;
    let renders = 0;
    const model = api().createController({
        request: async (id, body) => body
            ? new Promise((_resolve, reject) => { fail = reject; })
            : {revision: 1, notes: id, directories: [], command_sets: []},
        changed: () => { renders += 1; },
    });
    await model.open('one');
    model.update({notes: 'keep on error'});
    const saving = model.save();
    await model.open('two');
    const beforeFailure = renders;
    fail(Object.assign(new Error(), {code:'conflict'}));
    assert.equal(await saving, false);
    assert.equal(renders, beforeFailure);
    assert.equal(model.state.error, null);
    assert.equal(model.state.saving, false);
    await model.open('one');
    assert.equal(model.state.content.notes, 'keep on error');
    assert.equal(model.state.error, 'conflict');
    assert.equal(model.state.dirty, true);
    assert.equal(model.state.saving, false);
});

test('a session without its own saved host uses the saved host with the same destination and route', () => {
    const {profileFor} = api();
    const profiles = [
        {id: 'direct', host: 'NAS.example.', port: 22, username: 'ops', updated_at: '2026-01-01'},
        {id: 'via-jump', host: 'nas.example', port: 22, username: 'ops', jump_host_id: 'bastion'},
        {id: 'other-user', host: 'nas.example', port: 22, username: 'root'},
        {id: 'newer', host: 'nas.example', port: 22, username: 'ops', updated_at: '2026-05-01'},
    ];
    assert.equal(profileFor({profileId: 'own', host: 'nas.example', port: 22, username: 'ops'}, profiles), 'own');
    assert.equal(profileFor({host: 'nas.example', port: 22, username: 'ops'}, profiles), 'newer');
    assert.equal(profileFor({host: 'nas.example', port: 22, username: 'ops', jumpHostId: 'bastion'}, profiles), 'via-jump');
    assert.equal(profileFor({host: 'nas.example', port: 2222, username: 'ops'}, profiles), null);
    assert.equal(profileFor(null, profiles), null);
});

test('actions work for a matched session without its own saved host', async () => {
    const active = {id: 's1', connected: true, profileId: null, host: 'nas.example', port: 22, username: 'ops'};
    const calls = [];
    const model = api().createController({request: async () => ({revision: 1, notes: 'n', directories: ['/srv'], command_sets: []}),
        getActiveSession: () => active, profiles: () => [{id: 'p', host: 'nas.example', port: 22, username: 'ops'}],
        directory: (...args) => calls.push(args)});
    await model.open('p', 's1');
    assert.equal(model.currentTarget(), active);
    assert.equal(await model.directory('/srv'), true);
    active.port = 2222;
    assert.equal(model.currentTarget(), null, 'a different destination is not this host');
});
