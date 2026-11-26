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

    // The members of a request the server knows; others are left out, as
    // the Python handlers ignored them.
    const pick = (data, names) => {
        const out = {};
        for (const name of names) {
            if (data[name] !== undefined && data[name] !== null) out[name] = data[name];
        }
        return out;
    };
    const REF = ['source_id', 'request_id'];
    // Python's numeric cursor 0 is the first page: the server takes no cursor.
    const cursorOf = data => (data.cursor === 0 || data.cursor === undefined || data.cursor === null ? {} : {cursor: data.cursor});
    const ref = reply => ({source_id: reply.source_id, request_id: reply.request_id});
    const without = (reply, ...names) => {
        const out = {...reply};
        for (const name of names) delete out[name];
        return out;
    };
    const withoutSuccess = reply => without(reply, 'success');

    // The failure as the file pages know it: the upper-case INVALID_REQUEST
    // of the Python file handlers and the correlation members Python sent
    // with the event (operation, source and request, path).
    const fileFailure = (operation, pathField, extra) => (failed, data) => {
        const out = {...failed, operation, ...pick(data, REF)};
        if (out.code === 'invalid_request') out.code = 'INVALID_REQUEST';
        if (pathField) out.path = data[pathField] ?? '';
        return extra ? {...out, ...extra(data)} : out;
    };

    const requests = {
        list_directory: {
            type: 'files.list',
            payload: data => ({...pick(data, REF), remote_path: data.remote_path ?? '.', ...cursorOf(data)}),
            push: [['directory_listing', (reply, data) => ({
                ...ref(reply), path: reply.path, files: reply.files || [], cursor: data.cursor ?? 0, next_cursor: reply.next_cursor ?? null,
            })]],
            errorEvent: true,
            failure: fileFailure('list_directory', 'remote_path', data => (data.cursor && data.cursor !== 0 ? {cursor: data.cursor} : {})),
        },
        cancel_directory_listing: {
            type: 'files.list.cancel',
            payload: data => ({...pick(data, [...REF, 'listing_request_id']), ...cursorOf(data)}),
            // Always a success: the answer never says whether a listing existed.
            ack: () => ({success: true}),
            failure: () => ({success: true}),
        },
        get_home_directory: {
            type: 'files.home',
            payload: data => pick(data, REF),
            push: [['home_directory', reply => ({...ref(reply), path: reply.path})]],
            errorEvent: true,
            failure: fileFailure('get_home_directory'),
        },
        preview_file: {
            type: 'files.preview',
            payload: data => pick(data, [...REF, 'path', 'offset', 'max_bytes', 'tail_lines']),
            push: [['preview_data', reply => withoutSuccess(reply)]],
            errorEvent: 'preview_error',
            failure: fileFailure('preview_file', 'path'),
        },
        download_file_binary: {
            type: 'files.preview.image',
            payload: data => ({...pick(data, [...REF, 'remote_path']), for_preview: data.for_preview === true}),
            push: [['file_download_ready_binary', reply => without(reply, 'success', 'path')]],
            errorEvent: true,
            failure: fileFailure('download_file_binary', 'remote_path'),
        },
        open_file_for_edit: {
            type: 'files.edit.open',
            payload: data => pick(data, [...REF, 'path']),
            push: [['edit_data', reply => withoutSuccess(reply)]],
            errorEvent: 'edit_error',
            failure: fileFailure('open_file_for_edit', 'path'),
        },
        save_file: {
            type: 'files.edit.save',
            payload: data => pick(data, [...REF, 'path', 'content', 'encoding', 'newline', 'expected_revision', 'replace_strategy', 'save_challenge']),
            push: [['file_saved', reply => withoutSuccess(reply)]],
            errorEvent: true,
            failure: fileFailure('save_file', 'path'),
        },
        create_directory: {
            type: 'files.mkdir',
            payload: data => pick(data, [...REF, 'remote_path']),
            push: [['directory_created', reply => ({path: reply.path, ...ref(reply)})]],
            errorEvent: true,
            failure: fileFailure('create_directory', 'remote_path'),
        },
        create_file: {
            type: 'files.create',
            payload: data => pick(data, [...REF, 'parent_path', 'name']),
            push: [['file_created', reply => ({path: reply.path, size: reply.size ?? 0, operation: 'create_file', ...ref(reply)})]],
            errorEvent: true,
            failure: fileFailure('create_file'),
        },
        rename_file: {
            type: 'files.rename',
            payload: data => pick(data, [...REF, 'old_path', 'new_path']),
            ack: reply => ({success: true, ...ref(reply), old_path: reply.old_path, new_path: reply.new_path}),
            push: [['file_renamed', reply => ({old_path: reply.old_path, new_path: reply.new_path, ...ref(reply)})]],
            errorEvent: true,
            failure: fileFailure('rename_file', 'old_path', data => ({old_path: data.old_path, new_path: data.new_path})),
        },
        delete_item: {
            type: 'files.delete',
            payload: data => pick(data, [...REF, 'path']),
            push: [['item_deleted', reply => ({path: reply.path, ...ref(reply)})]],
            errorEvent: true,
            failure: fileFailure('delete_item', 'path'),
        },
        file_source_disconnect: {
            type: 'files.source.close',
            payload: data => pick(data, REF),
            push: [['file_source_disconnect_success', reply => ({source_id: reply.source_id})]],
            errorEvent: true,
            failure: (failed, data) => ({...failed, source_id: data.source_id ?? null}),
        },
    };

    return Object.freeze({
        requests: Object.freeze(requests),
        // Events the frontend sends without an acknowledgement and answers
        // with a listener; a local reply keeps those views from waiting.
        unavailable: Object.freeze({
            probe_session_sftp: data => ['session_sftp_capability', {
                success: true, session_id: data.session_id, request_id: data.request_id,
                available: false, reason: UNAVAILABLE,
            }],
        }),
        // Feature groups of the preview notice: what this build does not
        // answer yet (SFTP sources, transfers, permissions).
        features: Object.freeze([
            ['files', /^(prepare_transfer|cancel_transfer|transfer_server_to_server|quick_|get_file_permissions|set_file_permissions|prepare_file_permissions|get_file_permissions_job|apply_file_permissions_job|cancel_file_permissions_job|probe_session_sftp|request_session_directory)/],
        ]),
    });
});
