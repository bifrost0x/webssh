/* Realtime shim, area "notes" (M1, HO3): the notepad.
 *
 * Part of the Socket.IO name table of realtime-catalog.js (shape described
 * there). The package that builds the area edits only this file.
 */
(function (root, factory) {
    const area = factory();
    if (typeof module === 'object' && module.exports) module.exports = area;
    if (root) {
        root.WebSSHRealtimeAreas = root.WebSSHRealtimeAreas || {};
        root.WebSSHRealtimeAreas['notes'] = area;
    }
})(typeof window !== 'undefined' ? window : globalThis, function () {
    'use strict';

    return Object.freeze({
        requests: Object.freeze({
            get_notepad: {type: 'notes.get', payload: () => ({}), push: [['notepad_data', a => ({notepad: a.text || ''})]], errorEvent: true},
            save_notepad: {type: 'notes.save', payload: data => ({text: data.text}), ack: () => ({success: true}), errorEvent: true},
        }),
    });
});
