(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (root) {
        root.ProfileLauncherUtils = api;
    }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    'use strict';

    function hasKey(keys, keyId) {
        return Boolean(keyId) && (Array.isArray(keys) ? keys : [])
            .some(key => key && key.id === keyId && key.usable === true);
    }

    function determineLaunchMode(profile, context = {}) {
        if (!profile || typeof profile !== 'object') {
            return 'review';
        }

        const keys = Array.isArray(context.keys) ? context.keys : [];
        const jumpHosts = Array.isArray(context.jumpHosts) ? context.jumpHosts : [];
        const needsTargetPassword = profile.auth_type === 'password';

        if (profile.auth_type === 'key') {
            if (!hasKey(keys, profile.key_id)) {
                return 'review';
            }
        } else if (
            profile.auth_type === 'tailscale'
            && profile.tailscale_authorized !== true
        ) {
            return 'review';
        } else if (!needsTargetPassword && profile.auth_type !== 'tailscale') {
            return 'review';
        }

        if (!profile.jump_host_id) {
            return needsTargetPassword ? 'password' : 'connect';
        }

        const jumpHost = jumpHosts.find(item => (
            item && item.id === profile.jump_host_id
        ));
        if (!jumpHost) {
            return 'review';
        }
        if (jumpHost.auth_type === 'password') {
            return needsTargetPassword ? 'password' : 'jump-host-password';
        }
        if (jumpHost.auth_type !== 'key' || !hasKey(keys, jumpHost.key_id)) {
            return 'review';
        }
        return needsTargetPassword ? 'password' : 'connect';
    }

    function formatEndpoint(profile) {
        const value = profile && typeof profile === 'object' ? profile : {};
        const username = String(value.username || '');
        const host = String(value.host || '');
        const port = Number(value.port) || 22;
        return `${username}@${host}:${port}`;
    }

    return { determineLaunchMode, formatEndpoint };
}));
