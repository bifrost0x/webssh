/* Realtime shim, area "commands" (CM1): commands and command sets.
 *
 * Part of the Socket.IO name table of realtime-catalog.js (shape described
 * there). The package that builds the area edits only this file.
 */
(function (root, factory) {
    const area = factory();
    if (typeof module === 'object' && module.exports) module.exports = area;
    if (root) {
        root.WebSSHRealtimeAreas = root.WebSSHRealtimeAreas || {};
        root.WebSSHRealtimeAreas['commands'] = area;
    }
})(typeof window !== 'undefined' ? window : globalThis, function () {
    'use strict';

    // The members a request carries, as far as the page sent them: the
    // server applies the rules of the Python release to presence and type.
    const pick = (...names) => data => {
        const out = {};
        if (data && typeof data === 'object') {
            for (const name of names) {
                if (Object.hasOwn(data, name) && data[name] !== undefined) out[name] = data[name];
            }
        }
        return out;
    };
    const command = pick('name', 'command', 'parameters', 'description', 'os', 'category');
    const commandUpdate = pick('command_id', 'name', 'command', 'parameters', 'description', 'os', 'category');
    const setRef = pick('command_set_id');
    const sets = result => ({success: true, command_sets: result.command_sets || []});

    return Object.freeze({
        requests: Object.freeze({
            list_commands: {
                type: 'commands.list',
                payload: data => ({os_filter: data?.os_filter ?? null}),
                push: [['commands_list', a => ({commands: a.commands || []})]],
                errorEvent: true,
            },
            add_command: {
                type: 'commands.add', payload: command,
                push: [['command_added', a => ({command: a.command})]], refresh: 'commands.list', errorEvent: true,
            },
            update_command: {
                type: 'commands.update', payload: commandUpdate,
                push: [['command_updated', a => a]], refresh: 'commands.list', errorEvent: true,
            },
            delete_command: {
                type: 'commands.delete', payload: pick('command_id'),
                push: [['command_deleted', a => ({command_id: a.command_id})]], refresh: 'commands.list', errorEvent: true,
            },
            list_command_sets: {
                type: 'commands.set.list', payload: () => ({}),
                ack: sets, push: [['command_sets_list', a => a]], errorEvent: true,
            },
            // The preview of a parameterised set: the values are sent once
            // and never stored. Python answered a failure without an error
            // event.
            resolve_command_set_parameters: {
                type: 'commands.set.resolve', payload: pick('command_set_id', 'values', 'use_sudo'),
            },
            save_command_set: {
                type: 'commands.set.save', payload: pick('id', 'name', 'description', 'use_sudo', 'parameters', 'steps'),
                push: [['command_set_saved', a => a]], refresh: 'commands.set.list', errorEvent: true,
            },
            duplicate_command_set: {
                type: 'commands.set.duplicate', payload: setRef,
                push: [['command_set_saved', a => a]], refresh: 'commands.set.list', errorEvent: true,
            },
            delete_command_set: {
                type: 'commands.set.delete', payload: setRef,
                push: [['command_set_deleted', a => a]], refresh: 'commands.set.list', errorEvent: true,
            },
            convert_legacy_command_set: {
                type: 'commands.set.convert', payload: pick('profile_id', 'name', 'description'),
                push: [['command_set_converted', a => a]], refresh: 'commands.set.list', errorEvent: true,
            },
        }),
        refresh: Object.freeze({
            'commands.list': ['commands_list', p => ({commands: p.commands || []})],
            'commands.set.list': ['command_sets_list', sets],
        }),
    });
});
