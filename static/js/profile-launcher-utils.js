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

    function inferProfileStartupMode(profile) {
        if (profile?.startup_mode) return profile.startup_mode;
        if (profile?.command_set_id) return 'command_set';
        if (profile?.command_id) return 'command';
        if (profile?.startup_commands) return 'free_text';
        return 'none';
    }

    function profilePostConnectPayload(profile) {
        const mode = inferProfileStartupMode(profile);
        if (mode === 'free_text') {
            return {
                startup_mode: 'free_text',
                startup_commands: profile.startup_commands || '',
            };
        }
        if (mode === 'command') {
            if (!profile.command_id) return null;
            const payload = {
                startup_mode: 'command',
                command_id: profile.command_id,
            };
            if (Object.prototype.hasOwnProperty.call(
                profile,
                'parameters_override',
            )) {
                payload.parameters_override = profile.parameters_override;
            }
            return payload;
        }
        if (mode === 'command_set') {
            return profile.command_set_id ? {
                startup_mode: 'command_set',
                command_set_id: profile.command_set_id,
            } : null;
        }
        return mode === 'none' ? { startup_mode: 'none' } : null;
    }

    function normalizedPort(value, defaultPort = 22) {
        const candidate = value === undefined || value === null || value === ''
            ? defaultPort
            : Number(value);
        return Number.isInteger(candidate)
            && candidate >= 1
            && candidate <= 65535
            ? candidate
            : null;
    }

    function buildDirectConnectionData(profile, context = {}) {
        if (determineLaunchMode(profile, context) !== 'connect') return null;

        const host = String(profile.host || '').trim();
        const username = String(profile.username || '').trim();
        const port = normalizedPort(profile.port);
        if (!host || !username || port === null) return null;

        const result = {
            host,
            port,
            username,
            auth_type: profile.auth_type,
        };
        if (profile.auth_type === 'key') result.key_id = profile.key_id;
        if (profile.use_tmux === true) result.use_tmux = true;

        const postConnect = profilePostConnectPayload(profile);
        if (!postConnect) return null;
        Object.assign(result, postConnect);

        if (!profile.jump_host_id) return result;

        const jumpHost = (
            Array.isArray(context.jumpHosts) ? context.jumpHosts : []
        ).find(item => item?.id === profile.jump_host_id);
        if (!jumpHost) return null;

        const jumpHostName = String(jumpHost.host || '').trim();
        const jumpUsername = String(jumpHost.username || '').trim();
        const jumpPort = normalizedPort(jumpHost.port);
        if (!jumpHostName || !jumpUsername || jumpPort === null) return null;

        const proxyJump = {
            jump_host_id: jumpHost.id,
            host: jumpHostName,
            port: jumpPort,
            username: jumpUsername,
            auth_type: jumpHost.auth_type,
        };
        if (jumpHost.auth_type === 'key') {
            if (!jumpHost.key_id) return null;
            proxyJump.key_id = jumpHost.key_id;
        }
        result.proxy_jump = proxyJump;
        return result;
    }

    function formatEndpoint(profile) {
        const value = profile && typeof profile === 'object' ? profile : {};
        const username = String(value.username || '');
        const host = String(value.host || '');
        const port = Number(value.port) || 22;
        return `${username}@${host}:${port}`;
    }

    return {
        buildDirectConnectionData,
        determineLaunchMode,
        formatEndpoint,
    };
}));
