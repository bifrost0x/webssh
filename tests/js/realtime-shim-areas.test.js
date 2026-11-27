const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const catalog = require('../../static/js/realtime-catalog.js');

const ROOT = path.join(__dirname, '../..');
const areaFile = name => path.join(ROOT, 'static/js', `realtime-shim-${name}.js`);

// The table as it was in one file before the split (M1), so the split
// changes nothing the frontend sees.
const M1_REQUESTS = ['list_profiles', 'save_profile', 'delete_profile', 'update_profile_organization',
    'move_profile', 'list_jump_hosts', 'save_jump_host', 'delete_jump_host', 'list_socks_proxies',
    'save_socks_proxy', 'delete_socks_proxy', 'list_keys', 'upload_key', 'rename_key', 'replace_key',
    'delete_key', 'set_theme', 'set_confirm_session_close', 'set_disconnect_session_action', 'get_notepad',
    'save_notepad'];
// Built by M2 packages since the split.
const M2_REQUESTS = ['ssh_gateway_answer', 'ssh_gateway_input', 'ssh_gateway_ack',
    'list_directory', 'cancel_directory_listing', 'get_home_directory', 'preview_file',
    'download_file_binary', 'open_file_for_edit', 'save_file', 'create_directory', 'create_file', 'rename_file',
    'delete_item', 'file_source_disconnect', 'quick_connect', 'quick_disconnect', 'probe_session_sftp',
    'request_session_directory',
    'list_smb_shares', 'save_smb_share', 'delete_smb_share', 'smb_quick_connect', 'smb_quick_connect_cancel'];
const M1_UNAVAILABLE = ['list_commands', 'list_command_sets', 'list_smb_shares', 'probe_session_sftp',
    'request_session_insights', 'request_session_runtime_inventory'];
// Areas built in M2 move their events from the unavailable replies to the
// requests (realtime-shim-<area>.js of the owning package).
const M2_REFRESH = ['smb.share.list'];
const M1_FEATURES = ['files', 'smb', 'commands', 'commandSets', 'insights', 'terminalTools'];

test('the split table equals the table of M1 plus the areas built since', () => {
    assert.deepEqual(Object.keys(catalog.REQUESTS).sort(), [...M1_REQUESTS, ...M2_REQUESTS].sort());
    assert.deepEqual(Object.keys(catalog.UNAVAILABLE_REPLIES).sort(), M1_UNAVAILABLE.filter(e => !M2_REQUESTS.includes(e)).sort());
    assert.deepEqual(Object.keys(catalog.REFRESH_PUSH), ['keys.list', ...M2_REFRESH]);
    assert.equal(catalog.featureOf('delete_command_set'), 'commandSets');
    assert.equal(catalog.featureOf('delete_command'), 'commands');
    // A built area has no feature of the preview notice any more.
    assert.equal(catalog.featureOf('smb_list'), 'other');
    assert.equal(catalog.featureOf('quick_sftp_open'), 'other');
    assert.equal(catalog.featureOf('get_file_permissions'), 'files');
    assert.equal(catalog.featureOf('ssh_gateway_quick_cancel'), 'terminalTools');
    assert.equal(catalog.featureOf('list_profiles'), 'other');
    const features = new Set(M1_FEATURES.filter(f => f !== 'smb'));
    for (const event of ['prepare_transfer', 'list_commands', 'save_command_set', 'request_session_insights', 'request_herdr_snapshot']) {
        assert.ok(features.has(catalog.featureOf(event)), event);
    }
});

test('every area has its own file and the catalog loads them all', () => {
    for (const name of catalog.AREAS) assert.ok(fs.existsSync(areaFile(name)), name);
    const files = fs.readdirSync(path.join(ROOT, 'static/js')).filter(f => /^realtime-shim-.+\.js$/.test(f));
    assert.deepEqual(files.sort(), catalog.AREAS.map(name => `realtime-shim-${name}.js`).sort());
});

// Loads the catalog in a fresh context with the given area sources.
function loadCatalog(areas) {
    const context = {console};
    context.window = context;
    vm.createContext(context);
    vm.runInContext(fs.readFileSync(path.join(ROOT, 'static/js/realtime-acks.js'), 'utf8'), context);
    for (const source of areas) vm.runInContext(source, context);
    vm.runInContext(fs.readFileSync(path.join(ROOT, 'static/js/realtime-catalog.js'), 'utf8'), context);
    return context.WebSSHRealtimeCatalog;
}

test('a missing area or an event in two areas stops the load', () => {
    const sources = catalog.AREAS.map(name => fs.readFileSync(areaFile(name), 'utf8'));
    assert.ok(loadCatalog(sources).REQUESTS.list_keys);
    assert.throws(() => loadCatalog(sources.slice(1)), /area hosts is not loaded/);
    const twice = sources.map((source, i) => (catalog.AREAS[i] === 'notes'
        ? source.replace("get_notepad: {", "list_keys: {type: 'keys.list'}, get_notepad: {")
        : source));
    assert.throws(() => loadCatalog(twice), /list_keys is in two areas/);
    const both = sources.map((source, i) => (catalog.AREAS[i] === 'commands'
        ? source.replace('list_commands: () =>', "list_keys: () => ['x', {}], list_commands: () =>")
        : source));
    assert.throws(() => loadCatalog(both), /list_keys is both built and unavailable/);
});
