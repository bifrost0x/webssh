const assert = require('node:assert/strict');
const test = require('node:test');
const wire = require('../../static/js/realtime-wire.js');

const hex = bytes => Buffer.from(bytes).toString('hex');

// Byte layouts as written by protocol.AppendFrame (internal/realtime/protocol).
test('input and ack frames use the 14-byte big-endian header of schema v1', () => {
    assert.equal(hex(wire.encodeInput(7, 1, new TextEncoder().encode('ls\r'), false)),
        '02' + '00' + '00000007' + '0000000000000001' + '6c730d');
    assert.equal(hex(wire.encodeInput(2147483647, 2 ** 40, new Uint8Array([0, 255]), true)),
        '02' + '01' + '7fffffff' + '0000010000000000' + '00ff');
    assert.equal(hex(wire.encodeAck(2, 99)), '03' + '00' + '00000002' + '0000000000000063');
});

test('output frames decode with flags, channel and sequence', () => {
    const bytes = Buffer.from('01' + '03' + '00000001' + '0000000000000005' + '1b5b324a', 'hex');
    const frame = wire.decodeFrame(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.length));
    assert.equal(frame.kind, wire.KIND.OUTPUT);
    assert.equal(frame.flags, wire.FLAG.RESET | wire.FLAG.REPLAY);
    assert.equal(frame.channel, 1);
    assert.equal(frame.seq, 5);
    assert.equal(Buffer.from(frame.data).toString(), '\x1b[2J');
});

test('frames the browser must not accept are rejected', () => {
    const frame = (kind, flags, channel, seq) => Buffer.from(kind + flags + channel + seq, 'hex');
    const cases = {
        short: Buffer.alloc(13),
        input: frame('02', '00', '00000001', '0000000000000001'),
        ack: frame('03', '00', '00000001', '0000000000000001'),
        unknownFlag: frame('01', '04', '00000001', '0000000000000001'),
        channelZero: frame('01', '00', '00000000', '0000000000000001'),
        channelHigh: frame('01', '00', '80000000', '0000000000000001'),
        unsafeSeq: frame('01', '00', '00000001', '0020000000000000'),
    };
    for (const [name, bytes] of Object.entries(cases)) {
        assert.equal(wire.decodeFrame(new Uint8Array(bytes)), null, name);
    }
});

test('encoding refuses channels and sequences outside the contract', () => {
    assert.throws(() => wire.encodeAck(0, 1), /channel/);
    assert.throws(() => wire.encodeAck(2 ** 31, 1), /channel/);
    assert.throws(() => wire.encodeAck(1, -1), /sequence/);
    assert.throws(() => wire.encodeAck(1, 2 ** 53), /sequence/);
});

test('envelopes are encoded and decoded strictly', () => {
    assert.equal(wire.encodeEnvelope('notes.get', {}, 'c1'), '{"v":1,"t":"notes.get","id":"c1","p":{}}');
    assert.equal(wire.encodeEnvelope('session.keepalive'), '{"v":1,"t":"session.keepalive","p":{}}');
    assert.throws(() => wire.encodeEnvelope('Bad Type', {}), /type/);
    assert.throws(() => wire.encodeEnvelope('notes.get', {}, 'bad id'), /id/);
    assert.deepEqual(wire.decodeEnvelope('{"v":1,"t":"result","id":"c1","p":{"ok":true}}'),
        {type: 'result', id: 'c1', payload: {ok: true}});
    for (const text of ['not json', '[]', '{"v":2,"t":"hello","p":{}}', '{"v":1,"t":"hello","p":[]}',
        '{"v":1,"t":"HELLO","p":{}}', '{"v":1,"t":"result","id":"a b","p":{}}', '{"v":1,"p":{}}']) {
        assert.equal(wire.decodeEnvelope(text), null, text);
    }
});
