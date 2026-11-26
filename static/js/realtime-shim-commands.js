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

    return Object.freeze({
        unavailable: Object.freeze({
            list_commands: () => ['commands_list', {commands: [], available: false}],
            list_command_sets: () => ['command_sets_list', {success: true, command_sets: [], available: false}],
        }),
        features: Object.freeze([
            ['commands', /^(list_commands|add_command|update_command|delete_command$)/],
            ['commandSets', /command_set/],
        ]),
    });
});
