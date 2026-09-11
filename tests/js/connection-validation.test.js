const assert = require('node:assert/strict');
const test = require('node:test');
const validation = require('../../static/js/connection-validation');

test('accepts hostname, IDN, IPv4 and IPv6 inputs supported by SSH validation', () => {
    for (const host of ['server', 'server.example.', 'münchen.example', '192.0.2.1',
        '2001:db8::10', '[2001:db8::10]', '::1', '::ffff:192.0.2.1', 'fe80::1%eth0']) {
        assert.equal(validation.isValidHost(host), true, host);
    }
    for (const host of ['', ':::', '2001:db8::gg', 'bad host', 'host/path', '-host', 'x'.repeat(64)]) {
        assert.equal(validation.isValidHost(host), false, host);
    }
});

test('username and port hints match backend-supported formats', () => {
    assert.equal(validation.isValidUsername('first.last'), true);
    assert.equal(validation.isValidUsername('user_name-1'), true);
    assert.equal(validation.isValidUsername('alice@example.com'), false);
    for (const port of ['0', '65536', '22x', '22.5', '1e3', '']) assert.equal(validation.isValidPort(port), false, port);
    for (const port of ['1', '22', '65535']) assert.equal(validation.isValidPort(port), true, port);
});
