/* Socket.IO event names of the existing frontend mapped to schema v1.
 *
 * Request events become one request with a result. The push events that
 * the Python release sent next to its acknowledgement are produced here
 * from that result, so the frontend modules keep their listeners. Events
 * without a v1 type are answered locally with not_available_in_preview.
 * Terminal events are handled by realtime-terminal.js.
 */
(function (root, factory) {
    const api = factory(root.WebSSHRealtimeAcks || (typeof require === 'function' ? require('./realtime-acks.js') : null));
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root) root.WebSSHRealtimeCatalog = api;
})(typeof window !== 'undefined' ? window : globalThis, function (acks) {
    'use strict';

    const UNAVAILABLE = 'not_available_in_preview';
    const ok = result => ({success: true, ...result});
    const KEYS_REFRESH = 'keys.list';
    // profile-manager.js answers these failures of key changes with a
    // step-up or a passphrase prompt and sends the request again.
    const keyChallenge = failed => failed.code === 'step_up_required' || failed.passphrase_required === true;

    // event: {type, payload?, ack?, push?: [[event, build]], errorEvent?, refresh?}
    // payload(data) builds the request; ack(result, data) the acknowledgement;
    // push builders get the acknowledgement and the request data. errorEvent
    // repeats a failure as the generic 'error' event, as Python did for that
    // event, except for failures the page answers itself (answeredByPage);
    // refresh names a list request whose result is pushed afterwards.
    const REQUESTS = Object.freeze({
        list_profiles: {type: 'hosts.profile.list', push: [['profiles_list', a => ({profiles: a.profiles || []})]], errorEvent: true},
        save_profile: {
            type: 'hosts.profile.save',
            payload: data => {
                const profile = {...data};
                delete profile.tailscale_authorized;
                return profile;
            },
            push: [['profile_saved', a => a]],
            errorEvent: true,
        },
        delete_profile: {
            type: 'hosts.profile.delete',
            ack: (result, data) => ok({profile_id: data.profile_id, ...result}),
            push: [['profile_deleted', a => a]],
            errorEvent: true,
        },
        update_profile_organization: {type: 'hosts.profile.organize'},
        move_profile: {type: 'hosts.profile.move'},
        list_jump_hosts: {type: 'hosts.jump.list', push: [['jump_hosts_list', a => ({jump_hosts: a.jump_hosts || []})]], errorEvent: true},
        save_jump_host: {type: 'hosts.jump.save', push: [['jump_host_saved', a => a]], errorEvent: true},
        delete_jump_host: {
            type: 'hosts.jump.delete',
            ack: (result, data) => ok({jump_host_id: data.jump_host_id, ...result}),
            push: [['jump_host_deleted', a => a]],
            errorEvent: true,
        },
        list_socks_proxies: {type: 'hosts.socks.list', push: [['socks_proxies_list', a => ({socks_proxies: a.socks_proxies || []})]], errorEvent: true},
        save_socks_proxy: {type: 'hosts.socks.save', push: [['socks_proxy_saved', a => a]], errorEvent: true},
        delete_socks_proxy: {
            type: 'hosts.socks.delete',
            ack: (result, data) => ok({socks_proxy_id: data.socks_proxy_id, ...result}),
            push: [['socks_proxy_deleted', a => a]],
            errorEvent: true,
        },
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
        set_theme: {type: 'settings.theme.set', push: [['theme_updated', (a, data) => ({theme: data.theme})]], errorEvent: true},
        set_confirm_session_close: {
            type: 'settings.confirm_close.set',
            // The stored value, never the requested one: app.js shows what it gets.
            ack: result => ok(typeof result.enabled === 'boolean' ? {confirm_session_close: result.enabled} : {}),
            errorEvent: true,
        },
        set_disconnect_session_action: {
            type: 'settings.disconnect_action.set',
            ack: result => ok(typeof result.action === 'string' ? {disconnect_session_action: result.action} : {}),
            errorEvent: true,
        },
        get_notepad: {type: 'notes.get', payload: () => ({}), push: [['notepad_data', a => ({notepad: a.text || ''})]], errorEvent: true},
        save_notepad: {type: 'notes.save', payload: data => ({text: data.text}), ack: () => ({success: true}), errorEvent: true},
    });

    // The pushed list a refresh request produces.
    const REFRESH_PUSH = Object.freeze({
        [KEYS_REFRESH]: ['keys_list', result => ({keys: result.keys || []})],
    });

    // Events the frontend sends without an acknowledgement and answers with a
    // listener; a local reply keeps those views from waiting for a timeout.
    const UNAVAILABLE_REPLIES = Object.freeze({
        list_commands: () => ['commands_list', {commands: [], available: false}],
        list_command_sets: () => ['command_sets_list', {success: true, command_sets: [], available: false}],
        list_smb_shares: () => ['smb_shares_list', {smb_shares: [], available: false}],
        probe_session_sftp: data => ['session_sftp_capability', {
            success: true, session_id: data.session_id, request_id: data.request_id,
            available: false, reason: UNAVAILABLE,
        }],
        request_session_insights: data => ['session_insights', {
            success: false, session_id: data.session_id, request_id: data.request_id, reason: UNAVAILABLE,
        }],
        request_session_runtime_inventory: data => ['session_runtime_inventory', {
            success: false, session_id: data.session_id, request_id: data.request_id, code: UNAVAILABLE,
        }],
    });

    // Feature groups for the preview notice; everything else is "other".
    const FEATURE_PATTERNS = [
        ['files', /^(list_directory|cancel_directory_listing|get_home_directory|create_directory|delete_item|rename_file|preview_file|open_file_for_edit|save_file|download_file_binary|prepare_transfer|cancel_transfer|transfer_server_to_server|file_|quick_|cancel_file_permissions_job|probe_session_sftp)/],
        ['smb', /^(smb_|list_smb_shares|save_smb_share|delete_smb_share)/],
        ['commands', /^(list_commands|add_command|update_command|delete_command$)/],
        ['commandSets', /command_set/],
        ['insights', /^request_session_(insights|runtime_inventory)$/],
        ['terminalTools', /^(request_herdr_snapshot|request_session_directory|ssh_gateway_)/],
    ];

    function featureOf(event) {
        const match = FEATURE_PATTERNS.find(([, pattern]) => pattern.test(event));
        return match ? match[0] : 'other';
    }

    // Correlation fields a generic 'error' event carries back, so that
    // handlers keyed by request can release their pending state.
    const CORRELATION_FIELDS = ['request_id', 'source_id', 'session_id', 'path', 'operation', 'client_request_id'];

    function correlation(data) {
        const fields = {};
        if (data && typeof data === 'object') {
            for (const field of CORRELATION_FIELDS) {
                if (data[field] !== undefined) fields[field] = data[field];
            }
        }
        return fields;
    }

    function unavailable(root) {
        const key = 'previewNotice.notAvailable';
        const text = root.i18n?.t?.(key);
        return {success: false, code: UNAVAILABLE, error: text && text !== key ? text : 'Not available in this preview yet.'};
    }

    // Tells the preview notice which feature the user just reached.
    function notifyUnavailable(root, event) {
        if (typeof root.dispatchEvent !== 'function' || typeof root.CustomEvent !== 'function') return;
        root.dispatchEvent(new root.CustomEvent('webssh:preview-unavailable', {
            detail: {event, feature: featureOf(event)},
        }));
    }

    // Routing. host: {root, request(type, payload), dispatch(event, ...args), later(fn)}.

    function mapped(host, entry, data, ack) {
        const payload = entry.payload ? entry.payload(data) : {...data};
        host.request(entry.type, payload).then(result => {
            if (!result.ok) {
                const failed = acks.failure(result.err);
                if (entry.errorEvent && !entry.answeredByPage?.(failed)) host.dispatch('error', {success: false, error: failed.error, code: failed.code});
                acks.answer(ack, result);
                return;
            }
            const reply = entry.ack ? entry.ack(result.p, data) : {success: true, ...result.p};
            for (const [event, build] of entry.push || []) host.dispatch(event, build(reply, data));
            ack?.(reply);
            if (entry.refresh) refresh(host, entry.refresh);
        });
    }

    function refresh(host, type) {
        host.request(type, {}).then(result => {
            const [event, build] = REFRESH_PUSH[type];
            if (result.ok) host.dispatch(event, build(result.p));
        });
    }

    function unmapped(host, event, data, ack) {
        const failed = unavailable(host.root);
        notifyUnavailable(host.root, event);
        const reply = Object.hasOwn(UNAVAILABLE_REPLIES, event) ? UNAVAILABLE_REPLIES[event] : null;
        const fields = correlation(data);
        host.later(() => {
            if (reply) {
                const [name, payload] = reply(data);
                host.dispatch(name, payload);
            }
            if (ack) ack(failed);
            else if (!reply && (fields.request_id || fields.source_id)) host.dispatch('error', {...failed, ...fields});
        });
    }

    // Sends a non-terminal event as its v1 request, or answers it locally.
    function route(host, event, data, ack) {
        if (Object.hasOwn(REQUESTS, event)) mapped(host, REQUESTS[event], data, ack);
        else unmapped(host, event, data, ack);
    }

    return Object.freeze({
        UNAVAILABLE,
        route,
        unavailable,
        notifyUnavailable,
        REQUESTS,
        REFRESH_PUSH,
        UNAVAILABLE_REPLIES,
        featureOf,
        correlation,
    });
});
