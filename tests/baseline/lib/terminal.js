'use strict';

// Terminal session over the same Socket.IO events the browser uses:
// ssh_connect -> ssh_host_key (TOFU decision) -> ssh_connected,
// ssh_input, ssh_output with per-chunk acknowledgement, ssh_disconnect.

let requestCounter = 0;

function requestId() {
    requestCounter += 1;
    return `req_${Date.now().toString(36)}_${requestCounter.toString(36).padStart(4, '0')}`;
}

// Routes ssh_output of one socket to its sessions. Each chunk is
// acknowledged on arrival; the browser acknowledges after xterm wrote it.
class OutputRouter {
    constructor(socket) {
        this.socket = socket;
        this.listeners = new Map();
        socket.on('ssh_output', (data, acknowledge) => {
            try {
                const listener = this.listeners.get(data?.session_id);
                if (listener) listener(typeof data.data === 'string' ? data.data : '');
            } finally {
                if (typeof acknowledge === 'function') acknowledge();
            }
        });
        socket.on('ssh_host_key', (data) => {
            socket.emit('ssh_host_key_decision', {
                prompt_id: data.prompt_id,
                client_request_id: data.client_request_id,
                accepted: true,
            });
        });
    }

    static for(socket) {
        if (!socket.__baselineRouter) socket.__baselineRouter = new OutputRouter(socket);
        return socket.__baselineRouter;
    }
}

class TerminalSession {
    constructor(socket, sessionId, connectedData) {
        this.socket = socket;
        this.sessionId = sessionId;
        this.connectedData = connectedData;
        this.buffer = '';
        this.received = 0;
        this.waiter = null;
        OutputRouter.for(socket).listeners.set(sessionId, (chunk) => this.onOutput(chunk));
    }

    static open(socket, target, timeoutMs = 30000) {
        OutputRouter.for(socket);
        const id = requestId();
        return new Promise((resolve, reject) => {
            const cleanup = () => {
                clearTimeout(timer);
                socket.off('ssh_connected', onConnected);
                socket.off('ssh_error', onError);
            };
            const onConnected = (data) => {
                if (data?.client_request_id !== id) return;
                cleanup();
                resolve(new TerminalSession(socket, data.session_id, data));
            };
            const onError = (data) => {
                if (data?.client_request_id !== id) return;
                cleanup();
                const error = new Error(`ssh_error:${data?.error || 'unknown'}`);
                error.payload = data;
                reject(error);
            };
            const timer = setTimeout(() => {
                cleanup();
                reject(new Error('ssh_connect_timeout'));
            }, timeoutMs);
            socket.on('ssh_connected', onConnected);
            socket.on('ssh_error', onError);
            socket.emit('ssh_connect', {
                host: target.host,
                port: target.port,
                username: target.username,
                auth_type: 'password',
                password: target.password,
                client_request_id: id,
            });
        });
    }

    onOutput(chunk) {
        this.received += chunk.length;
        this.buffer += chunk;
        if (this.buffer.length > 65536) this.buffer = this.buffer.slice(-65536);
        if (this.waiter && this.waiter.test(this)) {
            const { resolve } = this.waiter;
            this.waiter = null;
            resolve();
        }
    }

    send(data) {
        this.socket.emit('ssh_input', { session_id: this.sessionId, data });
    }

    // Waits until test(session) is true after the next output chunk.
    waitUntil(test, timeoutMs = 30000) {
        if (test(this)) return Promise.resolve();
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                this.waiter = null;
                reject(new Error(`terminal_wait_timeout; tail=${JSON.stringify(this.buffer.slice(-200))}`));
            }, timeoutMs);
            this.waiter = {
                test,
                resolve: () => {
                    clearTimeout(timer);
                    resolve();
                },
            };
        });
    }

    waitForText(text, timeoutMs) {
        return this.waitUntil((session) => session.buffer.includes(text), timeoutMs);
    }

    // Puts the shell into a known state: short prompt, then a marker.
    async prepare() {
        await this.waitUntil((session) => session.received > 0, 30000);
        this.buffer = '';
        this.send("export PS1='$ '; stty -ixon; echo PREPARED_\"\"OK\r");
        await this.waitForText('PREPARED_OK', 30000);
        await new Promise((resolve) => setTimeout(resolve, 100));
        this.buffer = '';
    }

    close() {
        OutputRouter.for(this.socket).listeners.delete(this.sessionId);
        this.socket.emit('ssh_disconnect', { session_id: this.sessionId });
    }
}

module.exports = { TerminalSession };
