/* Terminal side of the realtime compatibility shim.
 *
 * Maps the Socket.IO terminal events of the existing frontend to schema v1:
 * one client-allocated channel per attached session, raw output decoded as
 * UTF-8 per channel, one cumulative ack per channel and animation frame, and
 * Go-Back-N input frames. State lives per connection; create() is called
 * again for every new connection.
 */
(function (root, factory) {
    const load = (name, file) => root[name] || (typeof require === 'function' ? require(file) : null);
    const api = factory(load('WebSSHRealtimeWire', './realtime-wire.js'), load('WebSSHRealtimeAcks', './realtime-acks.js'));
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root) root.WebSSHRealtimeTerminal = api;
})(typeof window !== 'undefined' ? window : globalThis, function (wire, acks) {
    'use strict';

    const MAX_INPUT_BYTES = 128 * 1024;
    const ATTACH_RETRIES = 3;
    // Fields of SessionInfo that use "" for the null of the Python events.
    const NULLABLE = ['key_id', 'profile_id', 'via_jump', 'jump_host_id', 'socks_proxy_id',
        'tmux_session_name', 'display_name', 'detected_platform'];
    const TARGET_FIELDS = ['profile_id', 'host', 'username', 'password', 'key_id', 'jump_host_id', 'socks_proxy_id'];

    function sessionEvent(info, extra) {
        const fields = {...info};
        delete fields.last_seq;
        for (const name of NULLABLE) {
            if (fields[name] === '') fields[name] = null;
        }
        return {...fields, ...extra};
    }


    // Projects the Socket.IO ssh_connect payload onto terminal.open. Inline
    // jump hosts and SOCKS proxies, stored credentials and Tailscale are not
    // part of M1; tmux, herdr and the display name are not sent.
    function openTarget(data) {
        const authType = data.auth_type || (data.key_id ? 'key' : 'password');
        if (!['password', 'key'].includes(authType)) return null;
        if (data.credential_id || wire.isPlainObject(data.proxy_jump) || wire.isPlainObject(data.socks_proxy)) return null;
        const target = {auth_type: authType};
        for (const name of TARGET_FIELDS) {
            if (typeof data[name] === 'string' && data[name] !== '') target[name] = data[name];
        }
        const port = typeof data.port === 'string' && /^\d{1,5}$/.test(data.port) ? Number(data.port) : data.port;
        if (Number.isInteger(port) && port > 0) target.port = port;
        return target;
    }

    function create(host) {
        const encoder = new TextEncoder();
        const channels = new Map();
        const sessions = new Map();
        const prompts = new Map();
        const closedSessions = new Set();
        let nextChannel = 1;
        let flushScheduled = false;

        function allocate(state) {
            const channel = {
                id: nextChannel++, decoder: new TextDecoder('utf-8'), frames: [],
                ackQueue: [], ackedSeq: 0, sentSeq: 0, nextIseq: 1, awaitingResend: null, pendingInput: new Map(), ...state,
            };
            channels.set(channel.id, channel);
            return channel;
        }

        function bind(channel, sessionId) {
            channel.sessionId = sessionId;
            sessions.set(sessionId, channel);
            closedSessions.delete(sessionId);
        }

        function release(channel, reason) {
            if (!channel || channels.get(channel.id) !== channel) return;
            channels.delete(channel.id);
            if (sessions.get(channel.sessionId) === channel) sessions.delete(channel.sessionId);
            for (const entry of channel.pendingInput.values()) {
                host.answer(entry.ack, acks.transportFailure('unavailable', reason));
            }
            channel.pendingInput.clear();
        }

        // Output and acks ----------------------------------------------------

        function scheduleFlush() {
            if (flushScheduled) return;
            flushScheduled = true;
            host.schedule(flushAcks);
        }

        function flushAcks() {
            flushScheduled = false;
            for (const channel of channels.values()) {
                while (channel.ackQueue.length && channel.ackQueue[0].done) {
                    channel.ackedSeq = channel.ackQueue.shift().seq;
                }
                if (channel.ackedSeq > channel.sentSeq) {
                    channel.sentSeq = channel.ackedSeq;
                    host.sendBinary(wire.encodeAck(channel.id, channel.ackedSeq));
                }
            }
        }

        function deliver(channel, frame) {
            const entry = {seq: frame.seq, done: false};
            channel.ackQueue.push(entry);
            const text = channel.decoder.decode(frame.data, {stream: true});
            const accept = () => {
                if (entry.done) return;
                entry.done = true;
                if (channels.get(channel.id) === channel) scheduleFlush();
            };
            if (!text || host.listenerCount('ssh_output') === 0) {
                accept();
                return;
            }
            host.dispatch('ssh_output', {session_id: channel.sessionId, data: text, sequence: frame.seq}, accept);
        }

        function onFrame(frame) {
            const channel = channels.get(frame.channel);
            if (!channel) return;
            if (channel.mode === 'live') deliver(channel, frame);
            else channel.frames.push(frame);
        }

        // The channel accepts input as soon as the session is announced, so a
        // listener may type into it; output queued so far follows the event.
        function goLive(channel, frames, announce) {
            channel.mode = 'live';
            channel.frames = [];
            announce();
            for (const frame of frames) deliver(channel, frame);
        }

        // Attach and restore ---------------------------------------------------

        // Binds a session to a new channel with a full replay and announces it
        // as ssh_session_restored, which the frontend treats as authoritative.
        async function attach(info) {
            const channel = allocate({mode: 'attaching', sessionId: info.session_id});
            for (let attempt = 0; ; attempt += 1) {
                const result = await host.request('terminal.attach', {ch: channel.id, session_id: info.session_id, after_seq: 0});
                if (channels.get(channel.id) !== channel) return false;
                if (result.ok) {
                    bind(channel, info.session_id);
                    channel.info = info;
                    const watermark = Number(result.p?.seq) || 0;
                    const replay = channel.frames.filter(frame => frame.seq <= watermark);
                    const live = channel.frames.filter(frame => frame.seq > watermark);
                    const snapshot = replay.map(frame => channel.decoder.decode(frame.data, {stream: true})).join('');
                    channel.ackedSeq = watermark;
                    goLive(channel, live, () => host.dispatch('ssh_session_restored', sessionEvent(info, {
                        buffered_output: snapshot, output_sequence: watermark,
                    })));
                    scheduleFlush();
                    return true;
                }
                if (result.err?.code !== 'backpressure' || attempt >= ATTACH_RETRIES) {
                    // The page must not keep a tab that looks connected but
                    // has no stream behind it.
                    release(channel, 'attach failed');
                    closed(info.session_id, result.err?.message || result.err?.code);
                    return false;
                }
                channel.frames = [];
                await host.delay(Math.min(5000, Math.max(50, result.err.retry_after_ms || 500)));
            }
        }

        function restore(restorable) {
            const list = Array.isArray(restorable) ? restorable : [];
            return Promise.all(list.filter(info => typeof info?.session_id === 'string').map(attach));
        }

        function resync(payload) {
            const channel = sessions.get(payload.session_id) || channels.get(payload.ch);
            if (!channel || channel.mode !== 'live') return;
            const info = {...channel.info, session_id: channel.sessionId};
            release(channel, 'resync');
            host.send('terminal.detach', {ch: channel.id});
            attach(info);
        }

        // Connect ---------------------------------------------------------------

        async function connect(data) {
            const requestId = data.client_request_id;
            const target = openTarget(data);
            if (!target) {
                host.dispatch('ssh_error', {...host.unavailable(), client_request_id: requestId});
                return;
            }
            const channel = allocate({mode: 'opening', requestId});
            const result = await host.request('terminal.open', {
                ch: channel.id, request_id: requestId, cols: 80, rows: 24, target,
            });
            if (channels.get(channel.id) !== channel) return;
            if (!result.ok) {
                release(channel, 'open failed');
                host.dispatch('ssh_error', {
                    error: result.err.message || result.err.code, code: result.err.code,
                    client_request_id: requestId,
                    ...(result.err.retry_after_ms ? {retry_after_ms: result.err.retry_after_ms} : {}),
                });
                return;
            }
            const info = result.p?.info || {};
            const sessionId = result.p?.session_id || info.session_id;
            bind(channel, sessionId);
            channel.info = info;
            goLive(channel, channel.frames, () => host.dispatch('ssh_connected',
                sessionEvent(info, {session_id: sessionId, client_request_id: requestId})));
        }

        // Input -----------------------------------------------------------------

        function input(data, ack) {
            const channel = sessions.get(data.session_id);
            if (!channel || channel.mode !== 'live') {
                ack?.(acks.failure({code: 'not_found', message: 'Session not found'}, {session_id: data.session_id}));
                return;
            }
            const bytes = encoder.encode(String(data.data ?? ''));
            if (bytes.length === 0) {
                ack?.({success: true});
                return;
            }
            if (bytes.length > (host.inputLimit || MAX_INPUT_BYTES)) {
                const result = acks.failure({code: 'ssh_input_too_large', message: 'The input is too large.'}, {session_id: data.session_id});
                ack?.(result);
                host.dispatch('ssh_error', result);
                return;
            }
            const iseq = channel.nextIseq++;
            if (iseq === channel.awaitingResend) channel.awaitingResend = null;
            if (ack) channel.pendingInput.set(iseq, {ack, quiet: data.acknowledge_backpressure === true});
            host.sendBinary(wire.encodeInput(channel.id, iseq, bytes, Boolean(ack)));
        }

        function inputAck(payload) {
            const channel = channels.get(payload.ch);
            const entry = channel?.pendingInput.get(payload.iseq);
            if (!entry) return;
            channel.pendingInput.delete(payload.iseq);
            entry.ack({success: true});
        }

        // Go-Back-N: the server dropped the rejected frame and every later one.
        // The next frame reuses the rejected sequence. Pending acknowledgements
        // fail so ssh-input.js retries in order; lost keystrokes are reported
        // with ssh_error, as the Python release did.
        function inputRejected(payload) {
            const channel = channels.get(payload.ch);
            if (!channel || !Number.isSafeInteger(payload.iseq) || payload.iseq >= channel.nextIseq) return;
            // Until the rejected sequence was sent again, a further rejection
            // can only be a duplicate or late; honouring it would rewind input.
            if (channel.awaitingResend != null) return;
            channel.nextIseq = payload.iseq;
            channel.awaitingResend = payload.iseq;
            const err = {code: payload.code || 'ssh_input_backpressure', message: 'The terminal is not accepting input right now.', retry_after_ms: payload.retry_after_ms};
            const result = acks.failure(err, {session_id: channel.sessionId});
            const rejected = channel.pendingInput.get(payload.iseq);
            for (const [iseq, entry] of [...channel.pendingInput]) {
                if (iseq < payload.iseq) continue;
                channel.pendingInput.delete(iseq);
                entry.ack(result);
            }
            if (!rejected?.quiet) host.dispatch('ssh_error', result);
        }

        // Socket.IO events ------------------------------------------------------

        function settle(type, payload, ack, map, mapErr) {
            return host.request(type, payload).then(result => {
                host.answer(ack, result, map, mapErr);
                return result;
            });
        }

        // Reasons the cancellation handling of app.js knows; any other code is
        // passed on and shown as an unconfirmed cancellation.
        function cancelFailure(err, result) {
            const reasons = {not_found: 'not_found', conflict: 'already_committed'};
            const reason = result.transport ? 'unavailable' : (reasons[err.code] || err.code);
            return {success: false, cancelled: false, reason};
        }

        function closed(sessionId, reason) {
            const channel = sessions.get(sessionId);
            release(channel, 'closed');
            if (closedSessions.has(sessionId)) return;
            closedSessions.add(sessionId);
            if (closedSessions.size > 256) closedSessions.delete(closedSessions.values().next().value);
            host.dispatch('ssh_disconnected', {session_id: sessionId, reason: reason || 'closed'});
        }

        const EMITS = {
            ssh_connect: data => { connect(data); },
            ssh_input: input,
            keep_alive: () => host.send('session.keepalive', {}),
            ssh_resize: data => {
                const channel = sessions.get(data.session_id);
                if (channel) host.send('terminal.resize', {ch: channel.id, cols: Number(data.cols) || 0, rows: Number(data.rows) || 0});
            },
            save_session_name: data => host.send('terminal.rename', {session_id: data.session_id, name: String(data.display_name ?? '')}),
            ssh_connect_cancel: (data, ack) => settle('terminal.cancel', {request_id: data.client_request_id}, ack,
                () => ({success: true, cancelled: true}), cancelFailure),
            ssh_discard_late_connection: (data, ack) => {
                release(sessions.get(data.session_id), 'discarded');
                settle('terminal.discard_late', {session_id: data.session_id, request_id: data.client_request_id}, ack, () => ({success: true}));
            },
            ssh_disconnect: (data, ack) => settle('terminal.close', {session_id: data.session_id}, ack, () => ({success: true}))
                .then(result => {
                    if (result.ok) closed(data.session_id, 'closed');
                    else host.dispatch('ssh_error', acks.failure(result.err, {session_id: data.session_id}));
                }),
            ssh_host_key_decision: (data, ack) => settle('prompt.answer',
                {prompt_id: data.prompt_id, kind: 'host_key', accepted: data.accepted === true}, ack, () => ({success: true})),
            ssh_auth_banner_decision: (data, ack) => settle('prompt.answer',
                {prompt_id: data.prompt_id, kind: 'banner', accepted: data.accepted === true}, ack, () => ({success: true})),
        };

        const EVENTS = {
            'terminal.closed': p => closed(p.session_id, p.reason),
            'terminal.timeout_warning': p => host.dispatch('session_timeout_warning', {session_id: p.session_id}),
            'terminal.resync_required': resync,
            'terminal.input_rejected': inputRejected,
            'terminal.input_ack': inputAck,
            'prompt.host_key': p => {
                prompts.set(p.prompt_id, p.request_id);
                host.dispatch('ssh_host_key', {
                    prompt_id: p.prompt_id, client_request_id: p.request_id, context: p.context,
                    host: p.host, port: p.port, key_type: p.key_type, fingerprint: p.fingerprint,
                });
            },
            'prompt.banner': p => host.dispatch('ssh_auth_banner', {
                prompt_id: p.prompt_id, client_request_id: p.request_id, context: p.context,
                host: p.host, port: p.port, banner: p.banner,
            }),
            // A synthetic load stream of the end-to-end suite: the server binds
            // a channel the client never allocates (2^31 and above) to a
            // session name before its first frame; its output is delivered
            // and acknowledged like a terminal's.
            'e2e.output_stream': p => {
                if (!Number.isSafeInteger(p.ch) || p.ch < 2 ** 31 || p.ch > 2 ** 32 - 1 || typeof p.session_id !== 'string') return;
                if (channels.has(p.ch)) return;
                const channel = {
                    id: p.ch, decoder: new TextDecoder('utf-8'), frames: [], ackQueue: [], ackedSeq: 0, sentSeq: 0,
                    nextIseq: 1, awaitingResend: null, pendingInput: new Map(), mode: 'live',
                };
                channels.set(channel.id, channel);
                bind(channel, p.session_id);
            },
            // Only host-key prompts have a close event in the existing frontend;
            // a withdrawn banner is followed by ssh_error or ssh_connected.
            'prompt.closed': p => {
                if (!prompts.delete(p.prompt_id)) return;
                host.dispatch('ssh_host_key_closed', {prompt_id: p.prompt_id, client_request_id: p.request_id});
            },
        };

        return {
            handles: event => Object.hasOwn(EMITS, event),
            emit(event, data, ack) {
                EMITS[event](wire.isPlainObject(data) ? data : {}, ack);
            },
            onEvent(type, payload) {
                if (!Object.hasOwn(EVENTS, type)) return false;
                EVENTS[type](payload);
                return true;
            },
            onFrame,
            restore,
            reset() {
                for (const channel of [...channels.values()]) release(channel, 'disconnected');
                prompts.clear();
            },
            channelOf: sessionId => sessions.get(sessionId)?.id,
        };
    }

    return Object.freeze({create, openTarget, sessionEvent, MAX_INPUT_BYTES});
});
