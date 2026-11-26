/* Socket.IO-compatible client on the native realtime endpoint (webssh.v1).
 *
 * Loaded instead of socket.io.min.js by the pages of the Go server only, so
 * the existing frontend keeps using io(), emit, on, once, off, listeners,
 * timeout().emit, volatile, connected, id and socket.io.on(...). Emits made
 * while the connection is down are never buffered: they fail at once.
 */
(function (root, factory) {
    const load = (name, file) => root[name] || (typeof require === 'function' ? require(file) : null);
    const api = factory(
        root,
        load('WebSSHRealtimeEmitter', './realtime-emitter.js'),
        load('WebSSHRealtimeAcks', './realtime-acks.js'),
        load('WebSSHRealtimeWire', './realtime-wire.js'),
        load('WebSSHRealtimeCatalog', './realtime-catalog.js'),
        load('WebSSHRealtimeTerminal', './realtime-terminal.js'),
    );
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (typeof window !== 'undefined' && root === window) {
        root.WebSSHRealtimeShim = api;
        root.io = api.io;
    }
})(typeof window !== 'undefined' ? window : globalThis, function (root, emitter, acks, wire, catalog, terminal) {
    'use strict';

    const {Emitter} = emitter;
    const RESERVED = new Set(['connect', 'connect_error', 'disconnect', 'disconnecting', 'newListener', 'removeListener']);
    const MISMATCH_EVENT = 'socket_protocol_mismatch';
    // requestTimeout bounds a request without result; restoreTimeout bounds
    // how long connected waits for the restores (both shim options).
    const DEFAULTS = {
        requestTimeout: 60000, restoreTimeout: 3000,
        autoConnect: true, reconnection: true, reconnectionDelay: 1000,
        reconnectionDelayMax: 5000, randomizationFactor: 0.5, timeout: 20000,
    };

    function randomId() {
        const bytes = new Uint8Array(12);
        root.crypto.getRandomValues(bytes);
        return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
    }

    // The application root the page was served under, from the Socket.IO
    // path option the frontend passes ("<root>/socket.io").
    function basePath(options) {
        return String(options.path || '/socket.io').replace(/\/socket\.io\/?$/, '').replace(/\/+$/, '');
    }

    function endpointUrl(options) {
        const location = root.location;
        const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
        return `${scheme}//${location.host}${basePath(options)}/ws`;
    }

    // After this many failed connection attempts in a row the session
    // status endpoint decides whether retrying can help at all: a browser
    // cannot read why an upgrade was refused.
    const STATUS_AFTER_FAILURES = 3;

    // The readable text of a 1013 close: the reason without its
    // connection_limit_user: or connection_limit_server: prefix.
    function limitReason(reason) {
        const match = /^connection_limit_(user|server):\s*(.*)$/s.exec(String(reason || ''));
        return match ? {scope: match[1], message: match[2]} : {scope: '', message: String(reason || '')};
    }

    // The page's runtime limits (runtime-limits.js) bound one input frame.
    function inputLimit() {
        const configured = Number(root.WEBSSH_SSH_INPUT_LIMITS?.maxEventBytes);
        return Number.isSafeInteger(configured) && configured > 0 ? Math.min(configured, terminal.MAX_INPUT_BYTES) : terminal.MAX_INPUT_BYTES;
    }

    // The fields of persistent_session_available as the Python release sent
    // them for a detached tmux session; "" stands for null as in hello.
    const PERSISTENT_FIELDS = ['session_id', 'host', 'port', 'username', 'key_id', 'auth_type', 'jump_host_id',
        'socks_proxy_id', 'via_socks', 'profile_id', 'via_jump', 'reconnect_route_known', 'tmux_session_name', 'display_name'];

    function persistentEvent(info) {
        const fields = terminal.sessionEvent(info);
        return Object.fromEntries(PERSISTENT_FIELDS.map(name => [name, fields[name] ?? null]));
    }

    class RealtimeSocket extends Emitter {
        constructor(options = {}) {
            super();
            this.opts = {...DEFAULTS, ...options};
            this.url = endpointUrl(this.opts);
            this.connected = false;
            this.disconnected = true;
            this.id = undefined;
            this.flags = {};
            this.io = new Emitter();
            this.io.engine = {transport: {name: 'websocket'}, id: undefined};
            this.io.opts = this.opts;
            this._ws = null;
            this._pending = new Map();
            this._nextRequest = 1;
            this._attempts = 0;
            this._reconnectTimer = null;
            this._connectTimer = null;
            this._manual = false;
            this._terminal = null;
            this._statusPending = false;
            if (this.opts.autoConnect) this.connect();
        }

        get active() { return Boolean(this._ws || this._reconnectTimer); }

        get volatile() {
            this.flags.volatile = true;
            return this;
        }

        timeout(ms) {
            this.flags.timeout = ms;
            return this;
        }

        connect() {
            this._manual = false;
            if (this._ws) return this;
            root.clearTimeout(this._reconnectTimer);
            this._reconnectTimer = null;
            this._open();
            return this;
        }

        open() { return this.connect(); }

        disconnect() {
            this._manual = true;
            root.clearTimeout(this._reconnectTimer);
            this._reconnectTimer = null;
            const ws = this._ws;
            const wasConnected = this.connected;
            this._teardown();
            if (ws) {
                try { ws.close(1000); } catch { /* already closing */ }
            }
            if (wasConnected) this._dispatch('disconnect', 'io client disconnect');
            return this;
        }

        close() { return this.disconnect(); }

        emit(event, ...args) {
            const flags = this.flags;
            this.flags = {};
            if (RESERVED.has(event)) throw new Error(`"${event}" is a reserved event name`);
            let ack = typeof args.at(-1) === 'function' ? args.pop() : null;
            if (ack && Number.isFinite(flags.timeout)) ack = acks.timed(ack, flags.timeout);
            const data = args[0];
            if (!this.connected) {
                const offline = acks.transportFailure('unavailable', 'Not connected to WebSSH.');
                this._later(() => acks.answer(ack, offline));
                return this;
            }
            if (this._terminal.handles(event)) {
                this._terminal.emit(event, data, ack);
            } else {
                catalog.route(this._catalogHost(), event, wire.isPlainObject(data) ? data : {}, ack);
            }
            return this;
        }

        emitWithAck(event, ...args) {
            const timeout = this.flags.timeout;
            return new Promise((resolve, reject) => {
                const ack = Number.isFinite(timeout)
                    ? (error, response) => (error ? reject(error) : resolve(response))
                    : response => resolve(response);
                this.emit(event, ...args, ack);
            });
        }

        _later(fn) { root.setTimeout(fn, 0); }

        _catalogHost() {
            return {
                root,
                request: (type, payload) => this._request(type, payload),
                dispatch: (event, ...args) => this._dispatch(event, ...args),
                later: fn => this._later(fn),
            };
        }

        // Requests resolve with the v1 result; a lost connection or a
        // missing result becomes a failure, never a hanging promise.
        _request(type, payload) {
            return new Promise(resolve => {
                const ws = this._ws;
                if (!ws || !this.connected) {
                    resolve(acks.transportFailure('unavailable', 'Not connected to WebSSH.'));
                    return;
                }
                const id = `c${this._nextRequest++}`;
                const timer = root.setTimeout(() => {
                    this._pending.delete(id);
                    resolve(acks.transportFailure('timeout', 'The server did not answer in time.'));
                }, this.opts.requestTimeout);
                this._pending.set(id, {resolve, timer});
                try {
                    ws.send(wire.encodeEnvelope(type, payload, id));
                } catch {
                    root.clearTimeout(timer);
                    this._pending.delete(id);
                    resolve(acks.transportFailure('unavailable', 'The request could not be sent.'));
                }
            });
        }

        _send(type, payload) {
            if (this._ws && this.connected) this._ws.send(wire.encodeEnvelope(type, payload));
        }

        _sendBinary(bytes) {
            if (this._ws && this.connected) this._ws.send(bytes);
        }

        _terminalHost() {
            return {
                request: (type, payload) => this._request(type, payload),
                send: (type, payload) => this._send(type, payload),
                sendBinary: bytes => this._sendBinary(bytes),
                dispatch: (event, ...args) => this._dispatch(event, ...args),
                listenerCount: event => this.listeners(event).length,
                unavailable: () => catalog.unavailable(root),
                answer: acks.answer,
                inputLimit: inputLimit(),
                delay: ms => new Promise(resolve => root.setTimeout(resolve, ms)),
                schedule: fn => {
                    let done = false;
                    const run = () => {
                        if (done) return;
                        done = true;
                        fn();
                    };
                    // Hidden tabs pause animation frames; the timer keeps acks flowing.
                    root.requestAnimationFrame?.(run);
                    root.setTimeout(run, 50);
                },
            };
        }

        _open() {
            let ws;
            try {
                ws = new root.WebSocket(this.url, [wire.SUBPROTOCOL]);
            } catch (error) {
                this._dispatch('connect_error', error);
                this._scheduleReconnect();
                return;
            }
            ws.binaryType = 'arraybuffer';
            this._ws = ws;
            this._helloSeen = false;
            this._mismatch = false;
            this._connectTimer = root.setTimeout(() => {
                if (this._ws === ws && !this._helloSeen) ws.close(4000, 'connect timeout');
            }, this.opts.timeout);
            ws.onmessage = event => {
                if (this._ws === ws) this._message(ws, event.data);
            };
            ws.onclose = event => {
                if (this._ws === ws) this._closed(event.code, event.reason);
            };
            ws.onerror = () => {};
            // A server that does not speak v1 completes the upgrade without the
            // subprotocol; that is the same mismatch as close code 4001.
            ws.onopen = () => {
                if (this._ws !== ws || ws.protocol === wire.SUBPROTOCOL) return;
                this._mismatch = true;
                ws.close(4000, 'subprotocol');
            };
        }

        _violation(ws) {
            console.error('[WebSSH] Realtime protocol violation');
            try { ws.close(wire.CLOSE.PROTOCOL_VIOLATION, 'protocol violation'); } catch { /* closing */ }
        }

        _message(ws, data) {
            if (typeof data !== 'string') {
                const frame = this._helloSeen ? wire.decodeFrame(data) : null;
                if (!frame) this._violation(ws);
                else this._terminal.onFrame(frame);
                return;
            }
            const envelope = wire.decodeEnvelope(data);
            if (!envelope || (!this._helloSeen && envelope.type !== 'hello')) {
                this._violation(ws);
                return;
            }
            if (envelope.type === 'hello') this._hello(ws, envelope.payload);
            else if (envelope.type === 'result') this._result(envelope);
            else if (!this._terminal.onEvent(envelope.type, envelope.payload)) {
                const event = catalog.e2eEvent(envelope.type);
                if (event) this._dispatch(event, envelope.payload);
            }
        }

        _result(envelope) {
            const pending = this._pending.get(envelope.id);
            if (!pending) return;
            this._pending.delete(envelope.id);
            root.clearTimeout(pending.timer);
            const p = envelope.payload;
            pending.resolve(p.ok === true
                ? {ok: true, p: wire.isPlainObject(p.p) ? p.p : {}}
                : {ok: false, err: wire.isPlainObject(p.err) ? p.err : {code: 'internal'}});
        }

        _hello(ws, payload) {
            if (this._helloSeen) {
                this._violation(ws);
                return;
            }
            this._helloSeen = true;
            root.clearTimeout(this._connectTimer);
            const reconnected = this._attempts > 0;
            const attempts = this._attempts;
            this._attempts = 0;
            this._terminal = terminal.create(this._terminalHost());
            this.id = randomId();
            this.io.engine.id = this.id;
            this.connected = true;
            this.disconnected = false;
            if (reconnected) this.io._dispatch('reconnect', attempts);
            this._dispatch('connect');
            // Python sent ssh_session_restored before connected{success}.
            // Bounded, so one slow attach cannot hold back the whole page.
            const restored = this._terminal.restore(payload.restorable);
            const bound = new Promise(resolve => root.setTimeout(resolve, this.opts.restoreTimeout));
            Promise.race([restored, bound]).then(() => {
                if (this._ws !== ws || !this.connected) return;
                for (const info of Array.isArray(payload.persistent) ? payload.persistent : []) {
                    if (typeof info?.session_id === 'string') this._dispatch('persistent_session_available', persistentEvent(info));
                }
                this._dispatch('connected', {
                    status: 'success',
                    username: payload.user?.username,
                    wire_revision: root.WebSSHSocketProtocol?.WIRE_REVISION,
                });
            });
        }

        _teardown() {
            root.clearTimeout(this._connectTimer);
            this._ws = null;
            this.connected = false;
            this.disconnected = true;
            this.id = undefined;
            this.io.engine.id = undefined;
            this._terminal?.reset();
            this._terminal = null;
            const pending = [...this._pending.values()];
            this._pending.clear();
            for (const entry of pending) {
                root.clearTimeout(entry.timer);
                entry.resolve(acks.transportFailure('unavailable', 'The connection to WebSSH was lost.'));
            }
        }

        _closed(code, reason) {
            const wasConnected = this.connected;
            const mismatch = this._mismatch;
            this._mismatch = false;
            this._teardown();
            const C = wire.CLOSE;
            if (code === C.UNSUPPORTED_VERSION || mismatch) {
                const data = {status: 'reload_required', code: MISMATCH_EVENT, message: reason || 'Reload the page.'};
                if (wasConnected) {
                    this._dispatch('disconnect', 'io server disconnect');
                    this._dispatch(MISMATCH_EVENT, data);
                } else {
                    this._dispatch('connect_error', Object.assign(new Error(data.message), {data}));
                }
                return;
            }
            // A revoked or missing session does not heal by retrying; every
            // other close (connection limit 1013, maintenance or shutdown
            // 4503, a protocol violation) reconnects with backoff.
            const final = code === C.UNAUTHENTICATED;
            if (wasConnected) {
                this._dispatch('disconnect', final ? 'io server disconnect' : 'transport close');
            } else {
                let data;
                if (final) data = {code: 'authentication_required'};
                else if (code === C.TRY_AGAIN_LATER) data = {code: 'connection_limit', ...limitReason(reason)};
                const message = final ? 'unauthorized' : (data ? data.message || 'connection limit' : 'websocket error');
                this._dispatch('connect_error', Object.assign(new Error(message), data ? {data} : {}));
            }
            // A connection refused before hello has no other way to learn
            // that the session is gone; a live one ended with 4003 is left
            // to the page's own handling of io server disconnect.
            if (final && !wasConnected) this._checkStatus();
            else if (!final) this._scheduleReconnect();
        }

        // Asks GET <root>/api/realtime/status whether the session is still
        // valid (it changes nothing). Without a session the page goes to the
        // sign-in at once instead of retrying forever; a different schema or
        // a recovery session reloads the page.
        _checkStatus() {
            if (this._statusPending || typeof root.fetch !== 'function') return;
            this._statusPending = true;
            const base = basePath(this.opts);
            root.fetch(`${base}/api/realtime/status`, {credentials: 'same-origin', cache: 'no-store', headers: {Accept: 'application/json'}})
                .then(response => response.json().catch(() => null).then(body => {
                    if (response.status === 401) {
                        this._manual = true;
                        root.clearTimeout(this._reconnectTimer);
                        this._reconnectTimer = null;
                        root.location.assign(`${base}/login`);
                    } else if (response.ok && body && (body.schema !== wire.VERSION || body.recovery === true)) {
                        root.location.reload();
                    }
                }))
                .catch(() => { /* offline: keep retrying */ })
                .finally(() => { this._statusPending = false; });
        }

        _scheduleReconnect() {
            if (this._manual || !this.opts.reconnection || this._reconnectTimer) return;
            this._attempts += 1;
            const attempt = this._attempts;
            if (attempt % STATUS_AFTER_FAILURES === 0) this._checkStatus();
            const base = Math.min(this.opts.reconnectionDelay * 2 ** (attempt - 1), this.opts.reconnectionDelayMax);
            const jitter = base * this.opts.randomizationFactor * (Math.random() * 2 - 1);
            const delay = Math.max(0, Math.round(Math.min(base + jitter, this.opts.reconnectionDelayMax)));
            this._reconnectTimer = root.setTimeout(() => {
                this._reconnectTimer = null;
                if (this._manual || this._ws) return;
                this.io._dispatch('reconnect_attempt', attempt);
                this._open();
            }, delay);
        }
    }

    function io(uri, options) {
        return new RealtimeSocket(typeof uri === 'object' && uri !== null ? uri : (options || {}));
    }

    return Object.freeze({io, RealtimeSocket, endpointUrl, limitReason, STATUS_AFTER_FAILURES});
});
