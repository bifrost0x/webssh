/* Realtime shim, area "insights" (HO1): session insights and the runtime inventory.
 *
 * Part of the Socket.IO name table of realtime-catalog.js (shape described
 * there). The package that builds the area edits only this file.
 */
(function (root, factory) {
    const area = factory();
    if (typeof module === 'object' && module.exports) module.exports = area;
    if (root) {
        root.WebSSHRealtimeAreas = root.WebSSHRealtimeAreas || {};
        root.WebSSHRealtimeAreas['insights'] = area;
    }
})(typeof window !== 'undefined' ? window : globalThis, function () {
    'use strict';

    const UNAVAILABLE = 'not_available_in_preview';

    return Object.freeze({
        unavailable: Object.freeze({
            request_session_insights: data => ['session_insights', {
                success: false, session_id: data.session_id, request_id: data.request_id, reason: UNAVAILABLE,
            }],
            request_session_runtime_inventory: data => ['session_runtime_inventory', {
                success: false, session_id: data.session_id, request_id: data.request_id, code: UNAVAILABLE,
            }],
        }),
        features: Object.freeze([
            ['insights', /^request_session_(insights|runtime_inventory)$/],
        ]),
    });
});
