(function(root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (root) {
        root.WebSSHSocketProtocol = api;
    }
})(typeof window !== 'undefined' ? window : globalThis, function() {
    'use strict';

    const WIRE_REVISION = 1;
    const MISMATCH_EVENT = 'socket_protocol_mismatch';
    const RELOAD_GUARD_KEY = 'webssh:socket-protocol-reload';

    function mismatchMarker(payload) {
        const requiredRevision = Number.isInteger(payload?.required_revision)
            ? payload.required_revision
            : 'unknown';
        return `${WIRE_REVISION}:${requiredRevision}`;
    }

    function isCompatibleServer(payload) {
        return (
            payload?.status === 'success'
            && payload.wire_revision === WIRE_REVISION
        );
    }

    function createMismatchController(options = {}) {
        const storage = options.storage || null;
        const disconnect = options.disconnect;
        const reload = options.reload;
        const showManualReload = options.showManualReload;
        let handled = false;

        function clearReloadGuard() {
            try {
                storage?.removeItem(RELOAD_GUARD_KEY);
            } catch {
                // Restricted storage is a supported degraded browser mode.
            }
        }

        function markCompatible() {
            handled = false;
            // Keep the revision-pair guard for this tab. During a rolling
            // deployment a later reconnect can reach the incompatible backend
            // again; a newly loaded client revision computes a different marker.
        }

        function handleMismatch(payload = {}) {
            if (handled) return 'ignored';
            handled = true;

            try {
                disconnect?.();
            } catch {
                // Continue to the safe reload path even if disconnect fails.
            }

            const marker = mismatchMarker(payload);
            let reloadArmed = false;
            if (storage && typeof reload === 'function') {
                try {
                    if (storage.getItem(RELOAD_GUARD_KEY) !== marker) {
                        storage.setItem(RELOAD_GUARD_KEY, marker);
                        reloadArmed = (
                            storage.getItem(RELOAD_GUARD_KEY) === marker
                        );
                    }
                } catch {
                    reloadArmed = false;
                }
            }

            if (reloadArmed) {
                reload();
                return 'reload';
            }

            showManualReload?.(payload);
            return 'manual';
        }

        return Object.freeze({
            clearReloadGuard,
            handleMismatch,
            markCompatible,
        });
    }

    return Object.freeze({
        MISMATCH_EVENT,
        RELOAD_GUARD_KEY,
        WIRE_REVISION,
        createMismatchController,
        isCompatibleServer,
    });
});
