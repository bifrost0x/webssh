/* Wire format of the native realtime endpoint (schema webssh.v1).
 *
 * Text frames carry one JSON envelope {"v":1,"t":type,"id":id,"p":object}.
 * Binary frames carry terminal bytes behind a 14-byte big-endian header:
 * kind u8 | flags u8 | channel u32 | seq u64 | data.
 * The authoritative definition is internal/realtime/protocol.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root) root.WebSSHRealtimeWire = api;
})(typeof window !== 'undefined' ? window : globalThis, function () {
    'use strict';

    const VERSION = 1;
    const SUBPROTOCOL = `webssh.v${VERSION}`;
    const HEADER_LEN = 14;
    const KIND = Object.freeze({OUTPUT: 1, INPUT: 2, ACK: 3});
    const FLAG = Object.freeze({RESET: 1, REPLAY: 2, WANT_ACK: 1});
    const CLOSE = Object.freeze({
        TRY_AGAIN_LATER: 1013,
        UNSUPPORTED_VERSION: 4001,
        PROTOCOL_VIOLATION: 4002,
        UNAUTHENTICATED: 4003,
        SLOW_CONSUMER: 4008,
        MAINTENANCE: 4503,
    });
    const TYPE_PATTERN = /^[a-z0-9._-]{1,64}$/;
    const ID_PATTERN = /^[A-Za-z0-9:._-]{1,128}$/;
    const MAX_CHANNEL = 2 ** 31 - 1;

    function isPlainObject(value) {
        return value !== null && typeof value === 'object' && !Array.isArray(value);
    }

    function encodeEnvelope(type, payload, id) {
        if (!TYPE_PATTERN.test(type)) throw new Error('invalid message type');
        const envelope = {v: VERSION, t: type};
        if (id !== undefined) {
            if (!ID_PATTERN.test(id)) throw new Error('invalid message id');
            envelope.id = id;
        }
        envelope.p = isPlainObject(payload) ? payload : {};
        return JSON.stringify(envelope);
    }

    // Returns null for anything that is not a well-formed envelope; the
    // caller closes the connection as a protocol violation.
    function decodeEnvelope(text) {
        let envelope;
        try {
            envelope = JSON.parse(text);
        } catch {
            return null;
        }
        if (!isPlainObject(envelope) || envelope.v !== VERSION) return null;
        if (typeof envelope.t !== 'string' || !TYPE_PATTERN.test(envelope.t)) return null;
        if (envelope.id !== undefined && (typeof envelope.id !== 'string' || !ID_PATTERN.test(envelope.id))) {
            return null;
        }
        if (envelope.p !== undefined && !isPlainObject(envelope.p)) return null;
        return {type: envelope.t, id: envelope.id, payload: envelope.p || {}};
    }

    function validChannel(channel) {
        return Number.isInteger(channel) && channel >= 1 && channel <= MAX_CHANNEL;
    }

    // Channels the server binds itself (the synthetic streams of the
    // end-to-end suite) lie above MAX_CHANNEL; output and acks may use the
    // whole unsigned 32-bit range, input only the client's own channels.
    function validWireChannel(channel) {
        return Number.isInteger(channel) && channel >= 1 && channel <= 0xFFFFFFFF;
    }

    function encodeFrame(kind, flags, channel, seq, data) {
        if (!(kind === KIND.ACK ? validWireChannel(channel) : validChannel(channel))) throw new Error('invalid channel');
        if (!Number.isSafeInteger(seq) || seq < 0) throw new Error('invalid sequence');
        const body = data || new Uint8Array(0);
        const frame = new Uint8Array(HEADER_LEN + body.length);
        const view = new DataView(frame.buffer);
        view.setUint8(0, kind);
        view.setUint8(1, flags);
        view.setUint32(2, channel);
        view.setBigUint64(6, BigInt(seq));
        frame.set(body, HEADER_LEN);
        return frame;
    }

    function encodeInput(channel, iseq, data, wantAck) {
        return encodeFrame(KIND.INPUT, wantAck ? FLAG.WANT_ACK : 0, channel, iseq, data);
    }

    function encodeAck(channel, seq) {
        return encodeFrame(KIND.ACK, 0, channel, seq, null);
    }

    // Decodes a frame from the server. Only output frames travel in that
    // direction; sequences beyond 2^53 cannot be compared safely in the
    // browser and are rejected as well.
    function decodeFrame(buffer) {
        const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
        if (bytes.length < HEADER_LEN) return null;
        const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        const kind = view.getUint8(0);
        const seq = view.getBigUint64(6);
        if (kind !== KIND.OUTPUT || seq > BigInt(Number.MAX_SAFE_INTEGER)) return null;
        const flags = view.getUint8(1);
        if ((flags & ~(FLAG.RESET | FLAG.REPLAY)) !== 0) return null;
        const channel = view.getUint32(2);
        if (!validWireChannel(channel)) return null;
        return {kind, flags, channel, seq: Number(seq), data: bytes.subarray(HEADER_LEN)};
    }

    return Object.freeze({
        VERSION,
        SUBPROTOCOL,
        HEADER_LEN,
        KIND,
        FLAG,
        CLOSE,
        MAX_CHANNEL,
        isPlainObject,
        validChannel,
        encodeEnvelope,
        decodeEnvelope,
        encodeFrame,
        encodeInput,
        encodeAck,
        decodeFrame,
    });
});
