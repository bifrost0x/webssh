(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (root) {
        root.WebSSHSocketReconnect = api;
    }
})(typeof window !== 'undefined' ? window : globalThis, function () {
    'use strict';

    function create(socket, options = {}) {
        const schedule = options.schedule || setTimeout;
        const cancel = options.cancel || clearTimeout;
        const markerLifetime = options.markerLifetime || 5000;
        let pendingOutputResync = false;
        let markerTimer = null;

        function clear() {
            pendingOutputResync = false;
            if (markerTimer !== null) {
                cancel(markerTimer);
                markerTimer = null;
            }
        }

        function expectOutputResync() {
            clear();
            pendingOutputResync = true;
            markerTimer = schedule(clear, markerLifetime);
        }

        function handleDisconnect(reason) {
            const shouldReconnect = (
                pendingOutputResync && reason === 'io server disconnect'
            );
            clear();
            if (!shouldReconnect) return false;
            socket.connect();
            return true;
        }

        return { clear, expectOutputResync, handleDisconnect };
    }

    return { create };
});
