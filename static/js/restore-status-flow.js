(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (root) {
        root.WebSSHRestoreStatus = api;
    }
})(typeof window !== 'undefined' ? window : globalThis, function () {
    'use strict';

    const DEFAULT_STORAGE_KEY = 'webssh.restore.pending';
    const ACTIVE_STATES = new Set(['preparing', 'in_progress']);
    const TERMINAL_STATES = new Set([
        'succeeded', 'failed', 'rollback_failed'
    ]);

    function createRestoreStatusFlow(options) {
        const storage = options.storage;
        const storageKey = options.storageKey || DEFAULT_STORAGE_KEY;
        const schedule = options.schedule || setTimeout;
        const pollInterval = options.pollInterval || 900;
        const readyInterval = options.readyInterval || 1000;
        let memoryPending = false;

        function isPending() {
            try {
                return memoryPending || storage.getItem(storageKey) === '1';
            } catch {
                return memoryPending;
            }
        }

        function markPending() {
            memoryPending = true;
            try {
                storage.setItem(storageKey, '1');
            } catch {
                // Continue polling in memory when browser storage is blocked.
            }
        }

        function clearPending() {
            memoryPending = false;
            try {
                storage.removeItem(storageKey);
            } catch {
                // A storage failure must not hide the server result.
            }
        }

        function schedulePoll() {
            schedule(poll, pollInterval);
        }

        function scheduleReadyCheck() {
            schedule(waitUntilReady, readyInterval);
        }

        async function waitUntilReady() {
            try {
                if (await options.checkReady()) {
                    options.reload();
                    return;
                }
            } catch {
                // The process is expected to be unavailable during restart.
            }
            scheduleReadyCheck();
        }

        async function poll() {
            let status;
            try {
                status = await options.fetchStatus();
                if (!status || typeof status.state !== 'string') {
                    throw new TypeError('invalid restore status response');
                }
            } catch {
                options.presentRestarting();
                scheduleReadyCheck();
                return;
            }

            if (TERMINAL_STATES.has(status.state)) {
                clearPending();
                options.present(status);
                return;
            }
            if (ACTIVE_STATES.has(status.state)) {
                options.present(status);
                schedulePoll();
                return;
            }
            if (status.state === 'idle' && isPending()) {
                schedulePoll();
                return;
            }
            options.present(status);
        }

        function resume() {
            return isPending() ? poll() : Promise.resolve(false);
        }

        return {
            clearPending,
            isPending,
            markPending,
            poll,
            resume
        };
    }

    return { createRestoreStatusFlow };
});
