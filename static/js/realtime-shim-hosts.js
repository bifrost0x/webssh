/* Realtime shim, area "hosts" (M1, NW1): saved hosts, jump hosts and SOCKS5 proxies.
 *
 * Part of the Socket.IO name table of realtime-catalog.js (shape described
 * there). The package that builds the area edits only this file.
 */
(function (root, factory) {
    const area = factory();
    if (typeof module === 'object' && module.exports) module.exports = area;
    if (root) {
        root.WebSSHRealtimeAreas = root.WebSSHRealtimeAreas || {};
        root.WebSSHRealtimeAreas['hosts'] = area;
    }
})(typeof window !== 'undefined' ? window : globalThis, function () {
    'use strict';

    const ok = result => ({success: true, ...result});

    return Object.freeze({
        requests: Object.freeze({
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
        }),
    });
});
