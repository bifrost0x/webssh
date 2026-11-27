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

    const text = value => (typeof value === 'string' ? value : '');
    // The server answers every sample, also a refused one, with success
    // false; the page waits for the event, as it did for Python.
    const sample = data => ({session_id: text(data?.session_id), request_id: text(data?.request_id)});

    return Object.freeze({
        requests: Object.freeze({
            request_session_insights: {
                type: 'insights.sample',
                payload: data => ({...sample(data), ...(data?.include_diagnostics === true ? {include_diagnostics: true} : {})}),
                ack: result => result,
                push: [['session_insights', a => a]],
            },
            request_session_runtime_inventory: {
                type: 'inventory.sample',
                payload: sample,
                ack: result => result,
                push: [['session_runtime_inventory', a => a]],
            },
        }),
    });
});
