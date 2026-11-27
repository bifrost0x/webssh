/* Realtime shim, area "files" (FS1, FS2): the file workspace and the SFTP sources.
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

    // A large editor or image answer is parked on the server; the page
    // fetches it once over HTTP instead of through the realtime queue.
    const handoff = (host, result) => {
        const token = result.p && result.p.handoff;
        if (typeof token !== 'string' || token === '') return result;
        const lost = {ok: false, err: {code: 'SOURCE_UNAVAILABLE', message: 'The file is no longer available. Open it again.'}};
        if (typeof host.fetchJSON !== 'function') return lost;
        return host.fetchJSON(`/api/files/handoff/${encodeURIComponent(token)}`)
            .then(({ok, body}) => (ok && body && typeof body === 'object' ? {ok: true, p: body}
                : {ok: false, err: {code: body?.code || lost.err.code, message: body?.error || lost.err.message}}))
            .catch(() => lost);
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
            expand: handoff,
            push: [['file_download_ready_binary', reply => without(reply, 'success', 'path')]],
            errorEvent: true,
            failure: fileFailure('download_file_binary', 'remote_path'),
        },
        open_file_for_edit: {
            type: 'files.edit.open',
            payload: data => pick(data, [...REF, 'path']),
            expand: handoff,
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

    // Quick SFTP (FS2): the target fields of terminal.open. A saved password
    // is the credential the page picked, with the target token it
    // confirmed for a typed target.
    const QUICK_FIELDS = ['host', 'username', 'password', 'key_id', 'profile_id', 'jump_host_id', 'socks_proxy_id',
        'credential_target_token', 'client_request_id'];
    const quickTarget = data => {
        const out = pick(data, QUICK_FIELDS);
        for (const [name, value] of Object.entries(out)) if (typeof value !== 'string' || value === '') delete out[name];
        out.auth_type = data.key_id ? 'key' : 'password';
        // The page answers the prompts of a gateway selector.
        if (data.gateway_interaction === 1) out.interactive = true;
        const port = typeof data.port === 'string' && /^\d{1,5}$/.test(data.port) ? Number(data.port) : data.port;
        if (Number.isInteger(port) && port > 0) out.port = port;
        if (data.credential_id !== undefined && data.credential_id !== null) {
            out.saved_password = true;
            if (typeof data.credential_id === 'string' && data.credential_id !== '') out.credential_id = data.credential_id;
            delete out.password;
        }
        return out;
    };
    const quickError = (failed, data) => {
        const out = {error: failed.error};
        if (failed.code) out.code = failed.code;
        if (data.client_request_id) out.client_request_id = data.client_request_id;
        return out;
    };
    const capability = (data, extra) => ({
        session_id: typeof data.session_id === 'string' ? data.session_id : '',
        request_id: typeof data.request_id === 'string' ? data.request_id : '', ...extra,
    });

    Object.assign(requests, {
        quick_connect: {
            type: 'files.quick.open',
            payload: quickTarget,
            push: [['quick_connect_success', reply => withoutSuccess(reply)]],
            failurePush: [['quick_connect_error', quickError]],
        },
        // Cancels a Quick SFTP attempt through an SSH gateway that is still
        // asking; the acknowledgement is that of the Python handler.
        ssh_gateway_quick_cancel: {
            type: 'files.quick.cancel',
            payload: data => ({client_request_id: typeof data.client_request_id === 'string' ? data.client_request_id : ''}),
            ack: () => ({success: true}),
            failure: failed => ({success: false, reason: failed.code === 'conflict' ? 'already_committed' : 'not_found'}),
        },
        quick_disconnect: {
            type: 'files.quick.close',
            payload: data => pick(data, ['connection_id']),
            push: [['quick_disconnect_success', reply => ({connection_id: reply.connection_id})]],
            errorEvent: true,
            failure: failed => ({success: false, error: failed.error}),
        },
        probe_session_sftp: {
            type: 'files.session.probe',
            payload: data => pick(data, ['session_id', 'request_id']),
            push: [['session_sftp_capability', (reply, data) => capability(data, {success: true, available: reply.available === true})]],
            // A refused channel says resource_shortage; every other failure
            // is an unknown capability.
            failurePush: [['session_sftp_capability', (failed, data) => capability(data, {
                success: false, available: false, ...(failed.code === 'channel_rejected' ? {reason: 'resource_shortage'} : {}),
            })]],
        },
        request_session_directory: {
            type: 'files.session.directory',
            payload: data => pick(data, ['session_id']),
            ack: reply => ({success: Boolean(reply.directory), directory: reply.directory ?? null, reason: reply.reason ?? null}),
            failure: failed => ({success: false, directory: null, reason: failed.code === 'rate_limited' ? 'busy' : 'unavailable'}),
        },
    });


    // Permission changes and permission jobs (AU2, permissions.*). The
    // answers are pushed as the Python events with the correlation members;
    // failures are the generic error with the upper-case file codes.
    const permissionFailure = operation => (failed, data) => {
        const out = fileFailure(operation)(failed, data);
        if (out.code === 'busy') out.code = 'BUSY';
        return out;
    };
    const permissionEvent = (event, operation, type, names) => ({
        type,
        payload: data => pick(data, [...REF, ...names]),
        push: [[event, (reply, data) => ({...withoutSuccess(reply), operation, ...pick(data, REF)})]],
        errorEvent: true,
        failure: permissionFailure(operation),
    });
    Object.assign(requests, {
        get_file_permissions: permissionEvent('file_permissions', 'get_file_permissions', 'permissions.get', ['path']),
        set_file_permissions: permissionEvent('file_permissions_changed', 'set_file_permissions', 'permissions.set', ['path', 'mode', 'expected_metadata']),
        prepare_file_permissions: permissionEvent('file_permissions_job', 'prepare_file_permissions', 'permissions.job.prepare',
            ['paths', 'recursive', 'file_mode', 'directory_mode']),
        get_file_permissions_job: permissionEvent('file_permissions_job', 'get_file_permissions_job', 'permissions.job.get', ['job_id']),
        // Paths and modes belong to the server's plan; only the job is sent.
        apply_file_permissions_job: permissionEvent('file_permissions_job', 'apply_file_permissions_job', 'permissions.job.apply', ['job_id']),
        cancel_file_permissions_job: permissionEvent('file_permissions_job', 'cancel_file_permissions_job', 'permissions.job.cancel', ['job_id']),
    });

    return Object.freeze({
        requests: Object.freeze(requests),
    });
});
