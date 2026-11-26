/* Realtime shim, area "smb" (FS3): SMB shares.
 *
 * Part of the Socket.IO name table of realtime-catalog.js (shape described
 * there). The package that builds the area edits only this file.
 */
(function (root, factory) {
    const area = factory();
    if (typeof module === 'object' && module.exports) module.exports = area;
    if (root) {
        root.WebSSHRealtimeAreas = root.WebSSHRealtimeAreas || {};
        root.WebSSHRealtimeAreas['smb'] = area;
    }
})(typeof window !== 'undefined' ? window : globalThis, function () {
    'use strict';

    return Object.freeze({
        unavailable: Object.freeze({
            list_smb_shares: () => ['smb_shares_list', {smb_shares: [], available: false}],
        }),
        features: Object.freeze([
            ['smb', /^(smb_|list_smb_shares|save_smb_share|delete_smb_share)/],
        ]),
    });
});
