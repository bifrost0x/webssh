/* Ordered, UTF-8-safe transport for interactive SSH input and large paste. */
(function (root) {
    'use strict';

    const SAFE_FALLBACK_CHUNK_BYTES = 4 * 1024;
    const configuredMaxBytes = Number(
        root.WEBSSH_SSH_INPUT_LIMITS?.maxEventBytes,
    );
    const CHUNK_BYTES = Number.isSafeInteger(configuredMaxBytes)
        && configuredMaxBytes > 0
        ? Math.min(64 * 1024, configuredMaxBytes)
        : SAFE_FALLBACK_CHUNK_BYTES;
    const ACK_TIMEOUT_MS = 10000;
    const MAX_BACKPRESSURE_RETRIES = 240;
    const encoder = new TextEncoder();
    const decoder = new TextDecoder('utf-8', {fatal: true});
    const sessionQueues = new Map();

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

    function emitWithAck(socket, payload) {
        return new Promise((resolve, reject) => {
            const timeout = root.setTimeout(
                () => reject(new Error('SSH input acknowledgement timed out')),
                ACK_TIMEOUT_MS,
            );
            socket.emit('ssh_input', payload, acknowledgement => {
                root.clearTimeout(timeout);
                resolve(acknowledgement || {success: true});
            });
        });
    }

    function notifyFailure(message) {
        root.showNotification?.(message || 'SSH input could not be sent', 'error');
    }

    async function transmit(sessionId, chunks) {
        if (chunks.length === 1) {
            root.socket.emit('ssh_input', {session_id: sessionId, data: chunks[0]});
            return true;
        }

        try {
            for (const chunk of chunks) {
                let retries = 0;
                while (true) {
                    const result = await emitWithAck(root.socket, {
                        session_id: sessionId,
                        data: chunk,
                        acknowledge_backpressure: true,
                    });
                    if (result.success !== false) break;
                    if (
                        result.code !== 'ssh_input_backpressure'
                        || retries >= MAX_BACKPRESSURE_RETRIES
                    ) {
                        throw new Error(result.error || 'SSH input was rejected');
                    }
                    retries += 1;
                    const delay = Math.min(
                        5000,
                        Math.max(1, Number(result.retry_after_ms) || 1),
                    );
                    await new Promise(resolve => root.setTimeout(resolve, delay));
                }
            }
            return true;
        } catch (error) {
            notifyFailure(error.message);
            return false;
        }
    }

    function send(sessionId, value) {
        if (!root.socket || !sessionId || typeof value !== 'string' || !value) {
            return Promise.resolve(false);
        }
        const chunks = byteChunks(value);
        const pending = sessionQueues.get(sessionId);
        if (!pending && chunks.length === 1) {
            root.socket.emit('ssh_input', {
                session_id: sessionId,
                data: chunks[0],
            });
            return Promise.resolve(true);
        }

        const queued = pending
            ? pending.catch(() => false).then(() => transmit(sessionId, chunks))
            : transmit(sessionId, chunks);
        sessionQueues.set(sessionId, queued);
        queued.finally(() => {
            if (sessionQueues.get(sessionId) === queued) {
                sessionQueues.delete(sessionId);
            }
        });
        return queued;
    }

    root.SSHInput = Object.freeze({byteChunks, send, CHUNK_BYTES});
}(window));
