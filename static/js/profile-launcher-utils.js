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

    function normalizedGroup(profile) {
        return String(profile?.group || '').trim();
    }

    function usesAdvancedConnectionSettings(profile) {
        const value = profile && typeof profile === 'object' ? profile : {};
        const startupMode = String(value.startup_mode || '').trim();
        const hasPostConnect = (
            (startupMode && startupMode !== 'none')
            || Boolean(value.command_id)
            || Boolean(value.command_set_id)
            || Boolean(String(value.startup_commands || '').trim())
        );
        return Boolean(value.jump_host_id || value.use_tmux === true || hasPostConnect);
    }

    function compareText(left, right) {
        return String(left).localeCompare(String(right), undefined, {
            numeric: true,
            sensitivity: 'base',
        });
    }

    function validSortOrder(profile) {
        return Number.isInteger(profile?.sort_order)
            && profile.sort_order >= 0;
    }

    function compareProfileOrder(
        left,
        right,
        fallbackIndexes = new Map(),
        usePersistedOrder = true,
    ) {
        if (usePersistedOrder && left.sort_order !== right.sort_order) {
            return left.sort_order - right.sort_order;
        }

        const leftIndex = fallbackIndexes.get(left);
        const rightIndex = fallbackIndexes.get(right);
        if (Number.isInteger(leftIndex) && Number.isInteger(rightIndex)) {
            return leftIndex - rightIndex;
        }
        return compareText(left?.name || '', right?.name || '')
            || compareText(left?.host || '', right?.host || '')
            || compareText(left?.id || '', right?.id || '');
    }

    function filterAndSortProfiles(profiles, query = '') {
        const needle = String(query || '').trim().toLocaleLowerCase();
        const source = Array.isArray(profiles) ? profiles : [];
        const fallbackIndexes = new Map(source.map((profile, index) => (
            [profile, index]
        )));
        const completeOrderGroups = new Map();
        source.forEach(profile => {
            const key = normalizedGroup(profile).toLocaleLowerCase();
            completeOrderGroups.set(
                key,
                (completeOrderGroups.get(key) ?? true) && validSortOrder(profile),
            );
        });
        return source
            .filter(profile => profile && profile.id)
            .filter(profile => (
                !needle
                || [
                    profile.name,
                    profile.host,
                    profile.username,
                    normalizedGroup(profile),
                ].some(value => String(value || '')
                    .toLocaleLowerCase()
                    .includes(needle))
            ))
            .slice()
            .sort((left, right) => (
                Number(right.favorite === true)
                - Number(left.favorite === true)
                || compareText(normalizedGroup(left), normalizedGroup(right))
                || compareProfileOrder(
                    left,
                    right,
                    fallbackIndexes,
                    completeOrderGroups.get(
                        normalizedGroup(left).toLocaleLowerCase(),
                    ) === true,
                )
            ));
    }

    function resolveProfileDrop(
        profiles,
        profileId,
        targetGroup,
        targetBoundaryIndex,
    ) {
        const source = (Array.isArray(profiles) ? profiles : [])
            .filter(profile => profile && profile.id);
        const movedProfile = source.find(profile => profile.id === profileId);
        if (!movedProfile || !Number.isInteger(targetBoundaryIndex)
                || targetBoundaryIndex < 0) {
            return null;
        }

        const normalizedTarget = String(targetGroup || '').trim();
        const expectedSourceGroup = normalizedGroup(movedProfile);
        const fallbackIndexes = new Map(source.map((profile, index) => (
            [profile, index]
        )));
        const targetProfiles = source
            .filter(profile => (
                normalizedGroup(profile).toLocaleLowerCase()
                === normalizedTarget.toLocaleLowerCase()
            ));
        const targetHasCompleteOrder = targetProfiles.every(validSortOrder);
        targetProfiles
            .sort((left, right) => (
                compareProfileOrder(
                    left,
                    right,
                    fallbackIndexes,
                    targetHasCompleteOrder,
                )
            ));
        const visibleTargets = targetProfiles.filter(profile => (
            profile.favorite !== true
        ));
        let visibleBoundary = Math.min(
            targetBoundaryIndex,
            visibleTargets.length,
        );

        if (expectedSourceGroup.toLocaleLowerCase()
                === normalizedTarget.toLocaleLowerCase()) {
            const sourceIndex = visibleTargets.findIndex(profile => (
                profile.id === profileId
            ));
            if (sourceIndex < 0) return null;
            if (sourceIndex < visibleBoundary) visibleBoundary -= 1;
            if (sourceIndex === visibleBoundary) return null;
        }

        const remainingTargets = targetProfiles.filter(profile => (
            profile.id !== profileId
        ));
        const remainingVisibleTargets = remainingTargets.filter(profile => (
            profile.favorite !== true
        ));
        visibleBoundary = Math.min(
            visibleBoundary,
            remainingVisibleTargets.length,
        );
        let targetIndex = remainingTargets.length;
        if (remainingVisibleTargets.length && visibleBoundary === 0) {
            targetIndex = remainingTargets.indexOf(remainingVisibleTargets[0]);
        } else if (remainingVisibleTargets.length
                && visibleBoundary < remainingVisibleTargets.length) {
            targetIndex = remainingTargets.indexOf(
                remainingVisibleTargets[visibleBoundary],
            );
        } else if (remainingVisibleTargets.length) {
            targetIndex = remainingTargets.indexOf(
                remainingVisibleTargets.at(-1),
            ) + 1;
        }

        return {
            profileId,
            expectedSourceGroup,
            targetGroup: normalizedTarget,
            targetIndex,
        };
    }

    function buildProfileSections(profiles, query = '', labels = {}) {
        const sorted = filterAndSortProfiles(profiles, query);
        const favorites = sorted.filter(profile => profile.favorite === true);
        const groupLabels = new Map();
        sorted.forEach(profile => {
            const group = normalizedGroup(profile);
            const key = group.toLocaleLowerCase();
            if (group && !groupLabels.has(key)) groupLabels.set(key, group);
        });
        const grouped = new Map();
        const ungrouped = [];

        sorted.filter(profile => profile.favorite !== true).forEach(profile => {
            const group = normalizedGroup(profile);
            if (!group) {
                ungrouped.push(profile);
                return;
            }
            const key = group.toLocaleLowerCase();
            if (!grouped.has(key)) {
                grouped.set(key, {
                    key: `group:${key}`,
                    label: groupLabels.get(key) || group,
                    profiles: [],
                });
            }
            grouped.get(key).profiles.push(profile);
        });

        const sections = [];
        if (favorites.length) {
            sections.push({
                key: 'favorites',
                label: labels.favorites || 'Favorites',
                profiles: favorites,
            });
        }
        sections.push(...Array.from(grouped.values())
            .sort((left, right) => compareText(left.label, right.label)));
        if (ungrouped.length) {
            sections.push({
                key: 'ungrouped',
                label: labels.ungrouped || 'Ungrouped',
                profiles: ungrouped,
            });
        }
        return sections;
    }

    return {
        buildProfileSections,
        buildDirectConnectionData,
        determineLaunchMode,
        filterAndSortProfiles,
        formatEndpoint,
        resolveProfileDrop,
        usesAdvancedConnectionSettings,
    };
}));
