/* Socket.IO event names of the existing frontend mapped to schema v1.
 *
 * Request events become one request with a result. The push events that
 * the Python release sent next to its acknowledgement are produced here
 * from that result, so the frontend modules keep their listeners. Events
 * without a v1 type are answered locally with not_available_in_preview.
 * Terminal events are handled by realtime-terminal.js. The table itself is
 * split into one file per area (realtime-shim-<area>.js), loaded before
 * this file.
 */
(function (root, factory) {
    const load = (name, file) => root[name] || (typeof require === 'function' ? require(file) : null);
    // The areas of the name table, in this order (realtime-shim-<area>.js).
    const names = ['hosts', 'keys', 'settings', 'notes', 'files', 'smb', 'commands', 'insights', 'terminal-tools'];
    const areas = names.map(name => {
        const area = root.WebSSHRealtimeAreas?.[name] || (typeof require === 'function' ? require(`./realtime-shim-${name}.js`) : null);
        if (!area) throw new Error(`realtime shim: area ${name} is not loaded`);
        return [name, area];
    });
    const api = factory(load('WebSSHRealtimeAcks', './realtime-acks.js'), areas);
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root) root.WebSSHRealtimeCatalog = api;
})(typeof window !== 'undefined' ? window : globalThis, function (acks, areas) {
    'use strict';

    const UNAVAILABLE = 'not_available_in_preview';

    // Joins one table of every area; a name in two areas is a load error,
    // so two packages can never answer the same event.
    function join(table) {
        const out = {};
        for (const [name, area] of areas) {
            for (const [key, value] of Object.entries(area[table] || {})) {
                if (Object.hasOwn(out, key)) throw new Error(`realtime shim: ${key} is in two areas (${name})`);
                out[key] = value;
            }
        }
        return Object.freeze(out);
    }

    // Each area (realtime-shim-<area>.js) provides some of:
    //   requests:    event: {type, payload?, ack?, push?: [[event, build]], failure?: [[event, build]], errorEvent?, answeredByPage?, refresh?}
    //   refresh:     list request type: [event, build] pushed after a refresh
    //   unavailable: event: data => [event, payload], a local reply while the area is not built
    //   features:    [[feature, pattern]] for the preview notice
    //   events:      v1 server event type: payload => [event, data], dispatched as Socket.IO event
    // payload(data) builds the request; ack(result, data) the acknowledgement;
    // push builders get the acknowledgement and the request data. errorEvent
    // repeats a failure as the generic 'error' event, as Python did for that
    // event, except for failures the page answers itself (answeredByPage);
    // an event name instead of true repeats it as that event. failure(failed,
    // data) rebuilds the failure for the acknowledgement and the event (the
    // correlation members Python sent with it). refresh names a list request
    // whose result is pushed afterwards; failurePush builders
    // get the failure and the request data and are pushed on a failure (the
    // error events of their own the Python release sent).
    // Events without a v1 type are answered locally with not_available_in_preview.
    const REQUESTS = join('requests');
    const REFRESH_PUSH = join('refresh');
    const UNAVAILABLE_REPLIES = join('unavailable');
    const SERVER_EVENTS = join('events');
    for (const event of Object.keys(UNAVAILABLE_REPLIES)) {
        if (Object.hasOwn(REQUESTS, event)) throw new Error(`realtime shim: ${event} is both built and unavailable`);
    }
    // Feature groups for the preview notice; everything else is "other".
    const FEATURE_PATTERNS = areas.flatMap(([, area]) => area.features || []);

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
        // expand(host, result) may replace a successful result before it is
        // answered (a large answer fetched over HTTP).
        const expand = result => (result.ok && entry.expand ? entry.expand(host, result) : result);
        host.request(entry.type, payload).then(expand).then(result => {
            if (!result.ok) {
                const failed = entry.failure ? entry.failure(acks.failure(result.err), data) : acks.failure(result.err);
                // The details Python sent with the event too (usages of a
                // jump host or SOCKS5 proxy that cannot be deleted), unless
                // the page answers the failure itself.
                if (entry.errorEvent && !entry.answeredByPage?.(failed)) {
                    host.dispatch(entry.errorEvent === true ? 'error' : entry.errorEvent, {...failed});
                }
                for (const [event, build] of entry.failurePush || []) host.dispatch(event, build(failed, data));
                acks.answer(ack, result, null, entry.failure ? () => failed : undefined);
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

    // Hooks of the end-to-end suite: e2e_<name> is the request e2e.<name>
    // and is acknowledged with its result as the Python hooks returned it.
    // Only the test build of the server registers these types; a release
    // server answers unknown_type.
    const E2E_PREFIX = 'e2e_';

    function e2eEntry(event) {
        return {type: `e2e.${event.slice(E2E_PREFIX.length)}`, ack: result => result};
    }

    // Sends a non-terminal event as its v1 request, or answers it locally.
    function route(host, event, data, ack) {
        if (Object.hasOwn(REQUESTS, event)) mapped(host, REQUESTS[event], data, ack);
        else if (event.startsWith(E2E_PREFIX) && /^[a-z0-9_]{1,60}$/.test(event)) mapped(host, e2eEntry(event), data, ack);
        else unmapped(host, event, data, ack);
    }

    // Dispatches a server event of an area table; false when no area has it.
    function serverEvent(host, type, payload) {
        if (!Object.hasOwn(SERVER_EVENTS, type)) return false;
        const [name, data] = SERVER_EVENTS[type](payload && typeof payload === 'object' ? payload : {});
        host.dispatch(name, data);
        return true;
    }

    // The server event e2e.<name> as the Socket.IO event e2e_<name>, or null.
    function e2eEvent(type) {
        return /^e2e\.[a-z0-9_]{1,60}$/.test(type) ? `${E2E_PREFIX}${type.slice(4)}` : null;
    }

    return Object.freeze({
        AREAS: Object.freeze(areas.map(([name]) => name)),
        UNAVAILABLE,
        route,
        unavailable,
        notifyUnavailable,
        REQUESTS,
        REFRESH_PUSH,
        UNAVAILABLE_REPLIES,
        SERVER_EVENTS,
        serverEvent,
        featureOf,
        correlation,
        e2eEvent,
    });
});
