const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const vm = require('node:vm');
function load() {
    const context = { window: {}, document: { addEventListener() {} } };
    const file = 'static/js/credential-picker.js';
    if (fs.existsSync(file)) vm.runInNewContext(fs.readFileSync(file, 'utf8'), context);
    return context.window.CredentialPicker;
}
test('saved password requires an unlocked vault and an exact explicit resource', () => {
    const picker = load();
    assert.ok(picker, 'shared credential picker is available');
    const state = {profiles: [{id: 'jump:1', host: 'host', port: 22, username: 'alice'}], vault: {unlocked: true, credentials: [{profile_id: 'jump:1', valid: true}]}};
    const target = {host: 'host', port: '22', username: 'alice'};
    assert.equal(picker.available(state, 'jump:1', target), true);
    assert.equal(picker.available(state, '1', target), false);
    assert.equal(picker.available(state, 'jump:1', {...target, host: 'elsewhere'}), false);
    state.vault.credentials[0].valid = false;
    assert.equal(picker.available(state, 'jump:1', target), false);
    state.vault.credentials[0].valid = true;
    state.vault.unlocked = false;
    assert.equal(picker.available(state, 'jump:1', target), false);
});
test('SMB credential selection binds the share and domain as well as host and user', () => {
    const picker = load();
    assert.ok(picker, 'shared credential picker is available');
    const target = {host: 'nas', username: 'alice', share: 'docs', domain: 'office'};
    const state = {profiles: [{id: 'smb:1', ...target}], vault: {unlocked: true, credentials: [{profile_id: 'smb:1', valid: true}]}};
    assert.equal(picker.available(state, 'smb:1', target), true);
    assert.equal(picker.available(state, 'smb:1', {...target, share: 'private'}), false);
    assert.equal(picker.available(state, 'smb:1', {...target, domain: 'other'}), false);
});

test('SSH credential availability distinguishes an omitted direct route from a SOCKS route', () => {
    const picker = load();
    const target = {host: 'host', port: 22, username: 'alice', auth_type: 'password', jump_host_id: null};
    const resource = {id: 'profile', ...target, socks_proxy_id: 'proxy-a'};
    const state = {enabled: true, profiles: [resource], credentials: [{uses: [{resource_id: 'profile', valid: true}]}]};
    assert.equal(picker.available(state, 'profile', target), false);
    assert.equal(picker.available(state, 'profile', {...target, socks_proxy_id: 'proxy-a'}), true);
    assert.equal(picker.available(state, 'profile', {...target, socks_proxy_id: 'proxy-b'}), false);
    resource.socks_proxy_id = null;
    assert.equal(picker.available(state, 'profile', target), true);
    assert.equal(picker.available(state, 'profile', {...target, socks_proxy_id: 'proxy-a'}), false);
});
