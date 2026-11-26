/* Realtime shim, area "settings" (M1): account settings sent over the realtime connection.
 *
 * Part of the Socket.IO name table of realtime-catalog.js (shape described
 * there). The package that builds the area edits only this file.
 */
(function (root, factory) {
    const area = factory();
    if (typeof module === 'object' && module.exports) module.exports = area;
    if (root) {
        root.WebSSHRealtimeAreas = root.WebSSHRealtimeAreas || {};
        root.WebSSHRealtimeAreas['settings'] = area;
    }
})(typeof window !== 'undefined' ? window : globalThis, function () {
    'use strict';

    const ok = result => ({success: true, ...result});

    return Object.freeze({
        requests: Object.freeze({
            set_theme: {type: 'settings.theme.set', push: [['theme_updated', (a, data) => ({theme: data.theme})]], errorEvent: true},
            set_confirm_session_close: {
                type: 'settings.confirm_close.set',
                // The stored value, never the requested one: app.js shows what it gets.
                ack: result => ok(typeof result.enabled === 'boolean' ? {confirm_session_close: result.enabled} : {}),
                errorEvent: true,
            },
            set_disconnect_session_action: {
                type: 'settings.disconnect_action.set',
                ack: result => ok(typeof result.action === 'string' ? {disconnect_session_action: result.action} : {}),
                errorEvent: true,
            },
        }),
    });
});
