/* Realtime shim, area "transfer" (TR1): HTTP transfers and host-to-host copies.
 *
 * Part of the Socket.IO name table of realtime-catalog.js (shape described
 * there). The package that builds the area edits only this file.
 */
(function (root, factory) {
    const area = factory();
    if (typeof module === 'object' && module.exports) module.exports = area;
    if (root) {
        root.WebSSHRealtimeAreas = root.WebSSHRealtimeAreas || {};
        root.WebSSHRealtimeAreas['transfer'] = area;
    }
})(typeof window !== 'undefined' ? window : globalThis, function () {
    'use strict';

    const text = value => (typeof value === 'string' ? value : '');
    const pick = (data, names) => {
        const out = {};
        for (const name of names) {
            if (typeof data?.[name] === 'string') out[name] = data[name];
        }
        return out;
    };

    // The public failure of app/transfer_errors.py as the pages read it.
    const TRANSFER_CODES = new Set(['PERMISSION_DENIED', 'CONFLICT', 'NOT_FOUND', 'SHARE_UNAVAILABLE', 'TIMEOUT',
        'SOURCE_UNAVAILABLE', 'SOURCE_CHANGED', 'LIMIT_EXCEEDED', 'CANCELLED', 'ATOMIC_REPLACE_UNAVAILABLE',
        'TRANSFER_UNAVAILABLE']);
    const publicFailure = source => {
        const out = {};
        for (const name of ['error_code', 'error', 'retryable', 'limit_kind', 'limit_bytes', 'actual_bytes']) {
            if (source[name] !== undefined && source[name] !== null) out[name] = source[name];
        }
        return out;
    };
    const copyContext = data => ({
        source_id: data?.source_id ?? null,
        request_id: data?.request_id ?? null,
        destination_source_id: data?.destination_source_id ?? null,
    });

    // A failed copy request: the transfer failure of the server, or the
    // answer of the Python handler to a malformed request.
    const copyFailure = (failed, data) => {
        const out = {success: false, ...copyContext(data)};
        if (TRANSFER_CODES.has(failed.code)) {
            return {...out, ...publicFailure({...failed, error_code: failed.code})};
        }
        if (failed.code === 'invalid_request' || failed.code === 'rate_limited' || failed.code === 'too_large') {
            return {...out, error: 'Missing required fields'};
        }
        return {...out, error_code: 'TRANSFER_UNAVAILABLE', error: 'The transfer could not be completed.', retryable: false};
    };

    const percent = (transferred, total) => (total ? Math.min(100, Math.floor(transferred * 100 / total)) : 0);

    return Object.freeze({
        requests: Object.freeze({
            prepare_transfer: {
                type: 'transfer.prepare',
                payload: data => {
                    const out = pick(data, ['source_id', 'request_id', 'direction', 'remote_path', 'conflict_policy']);
                    if (data?.archive) out.archive = true;
                    return out;
                },
                ack: reply => ({success: true, ...reply}),
                // Python answered every refusal with the same text.
                failure: (failed, data) => ({
                    success: false, error: 'Transfer unavailable', ...pick(data, ['source_id', 'request_id']),
                }),
            },
            cancel_transfer: {
                type: 'transfer.cancel',
                payload: data => ({transfer_id: text(data?.transfer_id)}),
                ack: reply => ({success: reply.state !== 'unavailable', state: reply.state}),
                failure: () => ({success: false, state: 'unavailable'}),
            },
            transfer_server_to_server: {
                type: 'transfer.copy',
                payload: data => {
                    const out = pick(data, ['source_id', 'request_id', 'source_path', 'destination_source_id', 'dest_path', 'conflict_policy']);
                    if (data?.is_dir === true) out.is_dir = true;
                    return out;
                },
                ack: reply => ({
                    success: true, transfer_id: reply.transfer_id, source_id: reply.source_id,
                    request_id: reply.request_id, destination_source_id: reply.destination_source_id,
                }),
                failure: copyFailure,
                failurePush: [['s2s_transfer_error', failed => {
                    const out = {...failed, transfer_id: null};
                    delete out.success;
                    return out;
                }]],
            },
        }),
        events: Object.freeze({
            'transfer.progress': p => (p.copy
                ? ['s2s_transfer_progress', {
                    ...copyContext(p.copy), transfer_id: p.transfer_id, filename: text(p.filename),
                    transferred: p.transferred, total: p.total, percent: percent(p.transferred, p.total), status: 'transferring',
                }]
                : ['transfer_progress', {transfer_id: p.transfer_id, direction: p.direction, transferred: p.transferred, total: p.total}]),
            'transfer.finished': p => {
                if (!p.copy) {
                    const out = {transfer_id: p.transfer_id, status: p.status, ...publicFailure(p)};
                    if (p.direction) out.direction = p.direction;
                    return ['transfer_finished', out];
                }
                if (p.status === 'completed') {
                    return ['s2s_transfer_complete', {
                        ...copyContext(p.copy), transfer_id: p.transfer_id, filename: text(p.filename),
                        source_path: text(p.source_path), dest_path: text(p.dest_path),
                    }];
                }
                return ['s2s_transfer_error', {...copyContext(p.copy), transfer_id: p.transfer_id, ...publicFailure(p)}];
            },
        }),
    });
});
