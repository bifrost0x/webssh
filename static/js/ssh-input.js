/* Ordered, UTF-8-safe transport for interactive SSH input and large paste. */
(function (root) {
    'use strict';

    const SAFE_FALLBACK_CHUNK_BYTES = 4 * 1024;
    const configuredMaxBytes = Number(root.WEBSSH_SSH_INPUT_LIMITS?.maxEventBytes);
    const CHUNK_BYTES = Number.isSafeInteger(configuredMaxBytes) && configuredMaxBytes > 0
        ? Math.min(64 * 1024, configuredMaxBytes) : SAFE_FALLBACK_CHUNK_BYTES;
    const ACK_TIMEOUT_MS = 10000;
    const MAX_BACKPRESSURE_RETRIES = 240;
    const encoder = new TextEncoder();
    const decoder = new TextDecoder('utf-8', {fatal: true});
    const sessionQueues = new Map();
    let observedSocket = null;

    function byteChunks(value, maxBytes = CHUNK_BYTES) {
        const bytes = encoder.encode(String(value));
        if (bytes.length <= maxBytes) return [String(value)];
        const chunks = [];
        let offset = 0;
        while (offset < bytes.length) {
            let end = Math.min(offset + maxBytes, bytes.length);
            while (end < bytes.length && (bytes[end] & 0xc0) === 0x80) end -= 1;
            if (end <= offset) throw new Error('Unable to split SSH input safely');
            chunks.push(decoder.decode(bytes.subarray(offset, end)));
            offset = end;
        }
        return chunks;
    }

    function normalizeNewlines(value) { return String(value).replace(/\r\n|\n/g, '\r'); }

    function notifyFailure(message) {
        root.showNotification?.(message || 'SSH input could not be sent', 'error');
    }

    function cancelQueue(queue, message) {
        if (queue.error) return;
        queue.error = new Error(message);
        if (sessionQueues.get(queue.sessionId) === queue) sessionQueues.delete(queue.sessionId);
        for (const cancel of queue.waiters) cancel(queue.error);
    }

    function cancelSession(sessionId) {
        const queue = sessionQueues.get(sessionId);
        if (queue) cancelQueue(queue, 'SSH input cancelled because the session ended');
    }

    function disconnected() {
        for (const queue of sessionQueues.values()) {
            cancelQueue(queue, 'SSH input cancelled because the connection was lost');
        }
    }

    function observeSocket() {
        if (observedSocket !== root.socket) {
            disconnected();
            observedSocket?.off?.('disconnect', disconnected);
            observedSocket = root.socket;
            observedSocket?.on?.('disconnect', disconnected);
        }
        return observedSocket;
    }

    function assertConnected(queue) {
        if (queue.error) throw queue.error;
        if (root.socket !== queue.socket || queue.socket.connected !== true) {
            throw new Error('SSH input cancelled because the connection was lost');
        }
    }

    // Both acknowledgement and backpressure waits are released on disconnect.
    function wait(queue, delay, payload) {
        return new Promise((resolve, reject) => {
            let settled = false;
            let timeout;
            const finish = (error, result) => {
                if (settled) return;
                settled = true;
                root.clearTimeout(timeout);
                queue.waiters.delete(cancel);
                if (error) reject(error);
                else resolve(result);
            };
            const cancel = error => finish(error);
            queue.waiters.add(cancel);
            timeout = root.setTimeout(() => finish(payload
                ? new Error('SSH input acknowledgement timed out') : null), delay);
            try {
                assertConnected(queue);
                if (payload) {
                    queue.socket.emit('ssh_input', payload, acknowledgement => {
                        finish(null, acknowledgement || {success: true});
                    });
                }
            } catch (error) {
                finish(error);
            }
        });
    }

    async function transmit(queue, chunks) {
        try {
            for (const chunk of chunks) {
                let retries = 0;
                while (true) {
                    assertConnected(queue);
                    const result = await wait(queue, ACK_TIMEOUT_MS, {
                        session_id: queue.sessionId,
                        data: chunk,
                        acknowledge_backpressure: true,
                    });
                    assertConnected(queue);
                    if (result.success !== false) break;
                    if (result.code !== 'ssh_input_backpressure' || retries >= MAX_BACKPRESSURE_RETRIES) {
                        throw new Error(result.error || 'SSH input was rejected');
                    }
                    retries += 1;
                    await wait(queue, Math.min(5000, Math.max(1, Number(result.retry_after_ms) || 1)));
                }
            }
            return true;
        } catch (error) {
            cancelQueue(queue, error.message);
            notifyFailure(error.message);
            return false;
        }
    }

    function send(sessionId, value) {
        const socket = observeSocket();
        if (!sessionId || typeof value !== 'string' || !value) return Promise.resolve(false);
        root.SessionDirectorySync?.noteInput(sessionId, value);
        if (socket?.connected !== true) {
            notifyFailure('SSH input could not be sent because the connection is offline');
            return Promise.resolve(false);
        }
        let chunks;
        try {
            chunks = byteChunks(value);
        } catch (error) {
            const pending = sessionQueues.get(sessionId);
            if (pending) cancelQueue(pending, error.message);
            notifyFailure(error.message);
            return Promise.resolve(false);
        }
        let queue = sessionQueues.get(sessionId);
        if (!queue && chunks.length === 1) {
            try {
                socket.emit('ssh_input', {session_id: sessionId, data: chunks[0]});
                return Promise.resolve(true);
            } catch (error) {
                notifyFailure(error.message);
                return Promise.resolve(false);
            }
        }
        if (!queue) {
            queue = {sessionId, socket, waiters: new Set(), error: null, tail: null};
            sessionQueues.set(sessionId, queue);
        }
        const queued = queue.tail
            ? queue.tail.then(success => success && !queue.error ? transmit(queue, chunks) : false)
            : transmit(queue, chunks);
        queue.tail = queued;
        queued.then(() => {
            if (queue.tail === queued && sessionQueues.get(sessionId) === queue) {
                sessionQueues.delete(sessionId);
            }
        });
        return queued;
    }

    function sendText(sessionId, value) {
        return send(sessionId, typeof value === 'string' ? normalizeNewlines(value) : value);
    }

    root.SSHInput = Object.freeze({
        byteChunks,
        send,
        sendText,
        cancelSession,
        hasPending: sessionId => sessionQueues.has(sessionId),
        CHUNK_BYTES,
    });
}(window));
