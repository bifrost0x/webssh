const test = require('node:test');
const assert = require('node:assert/strict');
const Discovery = require('../../static/js/host-discovery.js');

test('the suggested network is the /24 most saved IPv4 hosts share', () => {
    assert.equal(Discovery.suggestNetwork([{host: '10.0.0.5'}, {host: '192.168.1.2'}, {host: '192.168.1.9'}, {host: 'nas.local'}]), '192.168.1.0/24');
    assert.equal(Discovery.suggestNetwork([{host: '300.1.1.1'}, {host: 'fd00::1'}]), '');
    assert.equal(Discovery.suggestNetwork(), '');
});

test('ports accept up to three valid numbers and default to 22', () => {
    assert.deepEqual(Discovery.parsePorts(''), [22]);
    assert.deepEqual(Discovery.parsePorts('22, 2222 22'), [22, 2222]);
    assert.equal(Discovery.parsePorts('22,23,24,25'), null);
    assert.equal(Discovery.parsePorts('ssh'), null);
    assert.equal(Discovery.parsePorts('70000'), null);
});

test('a found endpoint becomes a new host with a short name', () => {
    assert.deepEqual(Discovery.prefill({address: '10.0.0.7', port: 2222, name: 'nas.home.arpa'}), {name: 'nas', host: '10.0.0.7', port: 2222});
    assert.deepEqual(Discovery.prefill({address: '10.0.0.8', port: 22, name: null}), {name: '10.0.0.8', host: '10.0.0.8', port: 22});
    assert.deepEqual(Discovery.prefill({address: '10.0.0.9', port: 22, name: null, platform: 'debian'}),
        {name: '10.0.0.9', host: '10.0.0.9', port: 22, platform: 'debian'}, 'the platform the SSH greeting named travels along');
});
