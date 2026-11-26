/* Realtime shim, area "terminal-tools" (HO1, TM1, NW2): Herdr, the session directory and the SSH gateway.
 *
 * Part of the Socket.IO name table of realtime-catalog.js (shape described
 * there). The package that builds the area edits only this file.
 */
(function (root, factory) {
    const area = factory();
    if (typeof module === 'object' && module.exports) module.exports = area;
    if (root) {
        root.WebSSHRealtimeAreas = root.WebSSHRealtimeAreas || {};
        root.WebSSHRealtimeAreas['terminal-tools'] = area;
    }
})(typeof window !== 'undefined' ? window : globalThis, function () {
    'use strict';

    return Object.freeze({
        features: Object.freeze([
            ['terminalTools', /^(request_herdr_snapshot|request_session_directory|ssh_gateway_)/],
        ]),
    });
});
