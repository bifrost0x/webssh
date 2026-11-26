/* Acknowledgement semantics of the Socket.IO client, shared by the shim and
 * its terminal part.
 *
 * A plain acknowledgement receives the response object. One created with
 * socket.timeout(ms) receives (error, response): Socket.IO passes an Error
 * when no response arrived, so a lost connection or a missing result fails
 * such a callback with an Error, while a server-side failure is a response.
 */
(function (root, factory) {
    const api = factory(root);
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root) root.WebSSHRealtimeAcks = api;
})(typeof window !== 'undefined' ? window : globalThis, function (root) {
    'use strict';

    const TIMEOUT_MESSAGE = 'operation has timed out';

    function failure(err, extra) {
        const result = {success: false, code: err.code, error: err.message || err.code, ...extra};
        if (err.retry_after_ms) result.retry_after_ms = err.retry_after_ms;
        return result;
    }

    // Results the shim produced itself because no answer arrived.
    function transportFailure(code, message) {
        return {ok: false, transport: true, err: {code, message}};
    }

    function timed(ack, ms) {
        let settled = false;
        const finish = (error, ...response) => {
            if (settled) return;
            settled = true;
            root.clearTimeout(timer);
            ack(error, ...response);
        };
        const timer = root.setTimeout(() => finish(new Error(TIMEOUT_MESSAGE)), ms);
        const wrapped = (...response) => finish(null, ...response);
        wrapped.timed = true;
        wrapped.fail = () => finish(new Error(TIMEOUT_MESSAGE));
        return wrapped;
    }

    // Answers ack with a v1 result: mapOk builds the success response,
    // mapErr (optional) the failure response.
    function answer(ack, result, mapOk, mapErr) {
        if (!ack) return;
        if (result.ok) ack(mapOk(result.p || {}));
        else if (result.transport && ack.timed) ack.fail();
        else ack(mapErr ? mapErr(result.err, result) : failure(result.err));
    }

    return Object.freeze({TIMEOUT_MESSAGE, failure, transportFailure, timed, answer});
});
