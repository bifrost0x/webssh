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
        load('WebSSHRealtimeWire', './realtime-wire.js'),
        load('WebSSHRealtimeCatalog', './realtime-catalog.js'),
        load('WebSSHRealtimeTerminal', './realtime-terminal.js'),
    );
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (typeof window !== 'undefined' && root === window) {
        root.WebSSHRealtimeShim = api;
        root.io = api.io;
    }
})(typeof window !== 'undefined' ? window : globalThis, function (root, emitter, wire, catalog, terminal) {
    'use strict';

    const {Emitter} = emitter;
    const RESERVED = new Set(['connect', 'connect_error', 'disconnect', 'disconnecting', 'newListener', 'removeListener']);
    const MISMATCH_EVENT = 'socket_protocol_mismatch';
    const REQUEST_TIMEOUT_MS = 60000;
    const DEFAULTS = {
        autoConnect: true, reconnection: true, reconnectionDelay: 1000,
        reconnectionDelayMax: 5000, randomizationFactor: 0.5, timeout: 20000,
    };

    function randomId() {
        const bytes = new Uint8Array(12);
        root.crypto.getRandomValues(bytes);
        return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
    }

    function endpointUrl(options) {
        const location = root.location;
        const base = String(options.path || '/socket.io').replace(/\/socket\.io\/?$/, '').replace(/\/+$/, '');
        const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
        return `${scheme}//${location.host}${base}/ws`;
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
            if (RESERVED.has(event)) throw new Error(`"${event}" is a reserved event name`);
            const flags = this.flags;
            this.flags = {};
            let ack = typeof args.at(-1) === 'function' ? args.pop() : null;
            if (ack && Number.isFinite(flags.timeout)) ack = this._withTimeout(ack, flags.timeout);
            const data = args[0];
            if (!this.connected) {
                if (ack) this._later(() => ack(catalog.failure({code: 'unavailable', message: 'Not connected to WebSSH.'})));
                return this;
            }
            if (this._terminal.handles(event)) {
                this._terminal.emit(event, data, ack);
            } else if (Object.hasOwn(catalog.REQUESTS, event)) {
                this._mapped(catalog.REQUESTS[event], wire.isPlainObject(data) ? data : {}, ack);
            } else {
                this._unavailable(event, wire.isPlainObject(data) ? data : {}, ack);
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

        // Socket.IO calls a timed acknowledgement with (error, ...response).
        _withTimeout(ack, ms) {
            let settled = false;
            const timer = root.setTimeout(() => finish(new Error('operation has timed out')), ms);
            function finish(error, ...response) {
                if (settled) return;
                settled = true;
                root.clearTimeout(timer);
                ack(error, ...response);
            }
            return (...response) => finish(null, ...response);
        }

        _later(fn) { root.setTimeout(fn, 0); }

        _mapped(entry, data, ack) {
            const payload = entry.payload ? entry.payload(data) : {...data};
            this._request(entry.type, payload).then(result => {
                if (!result.ok) {
                    const failed = catalog.failure(result.err);
                    if (entry.errorEvent) this._dispatch('error', {error: failed.error, code: failed.code});
                    ack?.(failed);
                    return;
                }
                const reply = entry.ack ? entry.ack(result.p, data) : {success: true, ...result.p};
                for (const [event, build] of entry.push || []) this._dispatch(event, build(reply, data));
                ack?.(reply);
                if (entry.refresh) this._refresh(entry.refresh);
            });
        }

        _refresh(type) {
            this._request(type, {}).then(result => {
                const [event, build] = catalog.REFRESH_PUSH[type];
                if (result.ok) this._dispatch(event, build(result.p));
            });
        }

        _unavailable(event, data, ack) {
            const failed = catalog.unavailable(root);
            catalog.notifyUnavailable(root, event);
            const reply = catalog.UNAVAILABLE_REPLIES[event];
            const correlation = catalog.correlation(data);
            this._later(() => {
                if (reply) {
                    const [name, payload] = reply(data);
                    this._dispatch(name, payload);
                }
                if (ack) ack(failed);
                else if (!reply && (correlation.request_id || correlation.source_id)) {
                    this._dispatch('error', {...failed, ...correlation});
                }
            });
        }

        // Requests resolve with the v1 result; a lost connection or a
        // missing result becomes a failure, never a hanging promise.
        _request(type, payload) {
            return new Promise(resolve => {
                const ws = this._ws;
                if (!ws || !this.connected) {
                    resolve({ok: false, err: {code: 'unavailable', message: 'Not connected to WebSSH.'}});
                    return;
                }
                const id = `c${this._nextRequest++}`;
                const timer = root.setTimeout(() => {
                    this._pending.delete(id);
                    resolve({ok: false, err: {code: 'timeout', message: 'The server did not answer in time.'}});
                }, REQUEST_TIMEOUT_MS);
                this._pending.set(id, {resolve, timer});
                try {
                    ws.send(wire.encodeEnvelope(type, payload, id));
                } catch {
                    root.clearTimeout(timer);
                    this._pending.delete(id);
                    resolve({ok: false, err: {code: 'invalid_request', message: 'The request could not be sent.'}});
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
            else this._terminal.onEvent(envelope.type, envelope.payload);
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
            this._terminal.restore(payload.restorable).then(() => {
                if (this._ws !== ws || !this.connected) return;
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
                entry.resolve({ok: false, err: {code: 'unavailable', message: 'The connection to WebSSH was lost.'}});
            }
        }

        _closed(code, reason) {
            const wasConnected = this.connected;
            this._teardown();
            const C = wire.CLOSE;
            if (code === C.UNSUPPORTED_VERSION) {
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
            // other close, a protocol violation included, reconnects with backoff.
            const final = code === C.UNAUTHENTICATED;
            if (wasConnected) {
                this._dispatch('disconnect', final ? 'io server disconnect' : 'transport close');
            } else {
                const data = code === C.UNAUTHENTICATED ? {code: 'authentication_required'} : undefined;
                this._dispatch('connect_error', Object.assign(new Error(final ? 'unauthorized' : 'websocket error'), data ? {data} : {}));
            }
            if (!final) this._scheduleReconnect();
        }

        _scheduleReconnect() {
            if (this._manual || !this.opts.reconnection || this._reconnectTimer) return;
            this._attempts += 1;
            const attempt = this._attempts;
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

    return Object.freeze({io, RealtimeSocket, endpointUrl});
});
