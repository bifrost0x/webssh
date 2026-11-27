/* Realtime shim, area "terminal-tools" (HO1, TM1, NW2): Herdr, the session directory and the SSH gateway.
 *
 * Part of the Socket.IO name table of realtime-catalog.js (shape described
 * there). The package that builds the area edits only this file.
 */
(function (root, factory) {
    const area = factory();
    if (typeof module === 'object' && module.exports) module.exports = area;
    if (root) {
        root.WebSSHRealtimeAreas = root.WebSSHRealtimeAreas || {};
        root.WebSSHRealtimeAreas['terminal-tools'] = area;
    }
})(typeof window !== 'undefined' ? window : globalThis, function () {
    'use strict';

    const text = value => (typeof value === 'string' ? value : '');
    const sequence = value => (Number.isSafeInteger(value) && value >= 0 ? value : 0);

    return Object.freeze({
        requests: Object.freeze({
            // HO1: the Herdr agents of a connected session, acknowledged as
            // the Python release answered request_herdr_snapshot.
            request_herdr_snapshot: {
                type: 'herdr.snapshot',
                payload: data => ({session_id: text(data?.session_id)}),
                ack: result => result,
            },
            // NW2: answers and the temporary terminal of a gateway attempt.
            ssh_gateway_answer: {
                type: 'prompt.respond',
                payload: data => ({
                    request_id: text(data.client_request_id), prompt_id: text(data.challenge_id),
                    answers: Array.isArray(data.answers) ? data.answers.map(text) : [],
                }),
                ack: () => ({success: true}),
            },
            ssh_gateway_input: {
                type: 'gateway.input',
                payload: data => ({request_id: text(data.client_request_id), data: text(data.data)}),
                ack: () => ({success: true}),
            },
            ssh_gateway_ack: {
                type: 'gateway.ack',
                payload: data => ({request_id: text(data.client_request_id), sequence: sequence(data.sequence)}),
                ack: () => ({success: true}),
            },
        }),
        events: Object.freeze({
            'prompt.interactive': p => ['ssh_gateway_challenge', {
                client_request_id: p.request_id, challenge_id: p.prompt_id, context: p.context,
                title: text(p.title), instructions: text(p.instructions),
                prompts: (Array.isArray(p.prompts) ? p.prompts : []).map(q => ({label: text(q?.label), echo: q?.echo === true})),
            }],
            'gateway.setup': p => ['ssh_gateway_progress', {client_request_id: p.request_id, phase: text(p.phase)}],
            'gateway.output': p => ['ssh_gateway_output', {
                client_request_id: p.request_id, sequence: p.sequence, data: text(p.data),
            }],
        }),
    });
});
