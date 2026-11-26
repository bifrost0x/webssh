/* Realtime shim, area "keys" (M1): SSH keys.
 *
 * Part of the Socket.IO name table of realtime-catalog.js (shape described
 * there). The package that builds the area edits only this file.
 */
(function (root, factory) {
    const area = factory();
    if (typeof module === 'object' && module.exports) module.exports = area;
    if (root) {
        root.WebSSHRealtimeAreas = root.WebSSHRealtimeAreas || {};
        root.WebSSHRealtimeAreas['keys'] = area;
    }
})(typeof window !== 'undefined' ? window : globalThis, function () {
    'use strict';

    const ok = result => ({success: true, ...result});
    const KEYS_REFRESH = 'keys.list';
    // profile-manager.js answers these failures of key changes with a
    // step-up or a passphrase prompt and sends the request again.
    const keyChallenge = failed => failed.code === 'step_up_required' || failed.passphrase_required === true;

    return Object.freeze({
        requests: Object.freeze({
            list_keys: {type: 'keys.list', push: [['keys_list', a => ({keys: a.keys || []})]], errorEvent: true},
            upload_key: {type: 'keys.upload', push: [['key_uploaded', a => ({key: a.key})]], errorEvent: true, answeredByPage: keyChallenge},
            rename_key: {type: 'keys.rename', push: [['key_renamed', a => a]], errorEvent: true, refresh: KEYS_REFRESH},
            replace_key: {type: 'keys.replace', push: [['key_replaced', a => a]], errorEvent: true, answeredByPage: keyChallenge, refresh: KEYS_REFRESH},
            delete_key: {
                type: 'keys.delete',
                ack: (result, data) => ok({key_id: data.key_id, ...result}),
                push: [['key_deleted', a => ({key_id: a.key_id})]],
                errorEvent: true,
                answeredByPage: keyChallenge,
                refresh: KEYS_REFRESH,
            },
        }),
        // The pushed list a refresh request produces.
        refresh: Object.freeze({
            [KEYS_REFRESH]: ['keys_list', result => ({keys: result.keys || []})],
        }),
    });
});
