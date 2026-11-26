/* Realtime shim, area "files" (FS1, FS2): the file workspace over SFTP.
 *
 * Part of the Socket.IO name table of realtime-catalog.js (shape described
 * there). The package that builds the area edits only this file.
 */
(function (root, factory) {
    const area = factory();
    if (typeof module === 'object' && module.exports) module.exports = area;
    if (root) {
        root.WebSSHRealtimeAreas = root.WebSSHRealtimeAreas || {};
        root.WebSSHRealtimeAreas['files'] = area;
    }
})(typeof window !== 'undefined' ? window : globalThis, function () {
    'use strict';

    const UNAVAILABLE = 'not_available_in_preview';

    return Object.freeze({
        // Events the frontend sends without an acknowledgement and answers
        // with a listener; a local reply keeps those views from waiting.
        unavailable: Object.freeze({
            probe_session_sftp: data => ['session_sftp_capability', {
                success: true, session_id: data.session_id, request_id: data.request_id,
                available: false, reason: UNAVAILABLE,
            }],
        }),
        // Feature groups of the preview notice.
        features: Object.freeze([
            ['files', /^(list_directory|cancel_directory_listing|get_home_directory|create_directory|delete_item|rename_file|preview_file|open_file_for_edit|save_file|download_file_binary|prepare_transfer|cancel_transfer|transfer_server_to_server|file_|quick_|cancel_file_permissions_job|probe_session_sftp)/],
        ]),
    });
});
