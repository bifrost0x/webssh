/* Realtime shim, area "smb" (FS3): saved SMB shares and opening a share.
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

    const REQUEST_ID = /^[A-Za-z0-9:._-]{1,128}$/;
    const requestId = data => (typeof data?.request_id === 'string' && REQUEST_ID.test(data.request_id) ? data.request_id : '');

    // Codes of the v1 transport as the Python handlers spelled them. A
    // server without the area (SMB_ENABLED false) answers unknown_type.
    const TRANSPORT_CODES = {
        unknown_type: 'SMB_DISABLED',
        rate_limited: 'RATE_LIMITED',
        invalid_request: 'INVALID_REQUEST',
        too_large: 'INVALID_REQUEST',
        busy: 'REQUEST_IN_PROGRESS',
        timeout: 'TIMEOUT',
        unavailable: 'CONNECTION_FAILED',
    };
    // Saved-password failures keep their code and text (credential_error).
    const CREDENTIAL_CODES = new Set(['https_required', 'vault_locked', 'vault_missing', 'credential_missing',
        'authentication_required', 'credential_unavailable', 'credential_target_changed', 'credentials_disabled']);

    // smb_share_error {action, error, request_id, code?}: Python sent a
    // code only for a disabled feature, a rate limit, a missing request
    // ID and unreadable storage.
    function shareError(action) {
        return (failed, data) => {
            const payload = {action, error: failed.error, request_id: action === 'list' ? '' : requestId(data)};
            const code = TRANSPORT_CODES[failed.code] || (failed.code === 'storage_error' ? 'storage_error' : null);
            if (code === 'SMB_DISABLED') payload.error = 'SMB is disabled';
            if (code) payload.code = code;
            return payload;
        };
    }

    // smb_quick_connect_error {request_id, code, diagnostic_id?}.
    function connectError(failed, data) {
        const payload = {request_id: requestId(data)};
        if (CREDENTIAL_CODES.has(failed.code)) return {...payload, error: failed.error, code: failed.code};
        payload.code = TRANSPORT_CODES[failed.code] || failed.code || 'CONNECTION_FAILED';
        if (typeof failed.diagnostic_id === 'string') payload.diagnostic_id = failed.diagnostic_id;
        return payload;
    }

    const shares = a => ({smb_shares: a.smb_shares || []});

    return Object.freeze({
        requests: Object.freeze({
            list_smb_shares: {type: 'smb.share.list', ack: shares, push: [['smb_shares_list', shares]], failurePush: [['smb_share_error', shareError('list')]]},
            save_smb_share: {
                type: 'smb.share.save',
                ack: (result, data) => ({success: true, request_id: requestId(data), share: result.share}),
                push: [['smb_share_saved', a => a]],
                failurePush: [['smb_share_error', shareError('save')]],
                refresh: 'smb.share.list',
            },
            delete_smb_share: {
                type: 'smb.share.delete',
                ack: (result, data) => ({success: true, request_id: requestId(data), share_id: result.share_id}),
                push: [['smb_share_deleted', a => a]],
                failurePush: [['smb_share_error', shareError('delete')]],
                refresh: 'smb.share.list',
            },
            smb_quick_connect: {
                type: 'smb.connect',
                push: [['smb_quick_connect_success', (a, data) => ({request_id: requestId(data), file_source: a.file_source})]],
                failurePush: [['smb_quick_connect_error', connectError]],
            },
            smb_quick_connect_cancel: {type: 'smb.connect.cancel'},
        }),
        refresh: Object.freeze({
            'smb.share.list': ['smb_shares_list', shares],
        }),
    });
});
