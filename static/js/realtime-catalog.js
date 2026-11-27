/* Socket.IO event names of the existing frontend mapped to schema v1.
 *
 * Request events become one request with a result. The push events that
 * the Python release sent next to its acknowledgement are produced here
 * from that result, so the frontend modules keep their listeners. An
 * event without a v1 type is answered locally with unknown_type; every
 * event the pages send has one (tests/js/realtime-shim-coverage.test.js).
 * Terminal events are handled by realtime-terminal.js. The table itself is
 * split into one file per area (realtime-shim-<area>.js), loaded before
 * this file.
 */
(function (root, factory) {
    const load = (name, file) => root[name] || (typeof require === 'function' ? require(file) : null);
    // The areas of the name table, in this order (realtime-shim-<area>.js).
    const names = ['hosts', 'keys', 'settings', 'notes', 'files', 'smb', 'transfer', 'commands', 'insights', 'terminal-tools'];
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

    const UNKNOWN = 'unknown_type';

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
    const REQUESTS = join('requests');
    const REFRESH_PUSH = join('refresh');
    const SERVER_EVENTS = join('events');

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

    // The answer to an event without a v1 type, with the text of the
    // server's unknown_type failure.
    function unknown() {
        return {success: false, code: UNKNOWN, error: 'Unknown message type.'};
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

    // Answers an event no table knows, so that a caller waiting for its
    // acknowledgement or a request id never hangs.
    function unmapped(host, event, data, ack) {
        const failed = unknown();
        const fields = correlation(data);
        console.error(`[WebSSH] Realtime event without a v1 type: ${event}`);
        host.later(() => {
            if (ack) ack(failed);
            else if (fields.request_id || fields.source_id) host.dispatch('error', {...failed, ...fields});
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
        UNKNOWN,
        route,
        unknown,
        REQUESTS,
        REFRESH_PUSH,
        SERVER_EVENTS,
        serverEvent,
        correlation,
        e2eEvent,
    });
});
