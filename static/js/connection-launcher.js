(function (root, factory) {
    const utils = typeof module === 'object' && module.exports
        ? require('./profile-launcher-utils.js')
        : root.ProfileLauncherUtils;
    const api = factory(utils);
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root?.document) root.ConnectionLauncher = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function (
    ProfileLauncherUtils,
) {
    'use strict';

    function createConnectionLauncher(deps) {
        const required = [
            'getProfile',
            'getContext',
            'getDefaultPaneIndex',
            'isBusy',
            'startConnection',
            'openReview',
            'notify',
            'refreshProfiles',
        ];
        required.forEach(name => {
            if (typeof deps?.[name] !== 'function') {
                throw new TypeError(
                    `ConnectionLauncher requires ${name}()`,
                );
            }
        });

        return {
            launch(profileId, paneIndex = null) {
                if (deps.isBusy()) {
                    deps.notify(
                        'connection.connectBusy',
                        'A connection attempt is already in progress.',
                        'info',
                    );
                    return 'rejected';
                }

                const profile = deps.getProfile(profileId);
                if (!profile) {
                    deps.notify(
                        'connection.profileUnavailable',
                        'This saved connection is no longer available.',
                        'warning',
                    );
                    deps.refreshProfiles();
                    return 'rejected';
                }

                const context = deps.getContext();
                const mode = ProfileLauncherUtils.determineLaunchMode(
                    profile,
                    context,
                );
                const targetPane = paneIndex ?? deps.getDefaultPaneIndex();
                if (mode === 'connect') {
                    const connectionData = (
                        ProfileLauncherUtils.buildDirectConnectionData(
                            profile,
                            context,
                        )
                    );
                    if (!connectionData) {
                        deps.openReview(profileId, targetPane, 'review');
                        return 'review';
                    }
                    return deps.startConnection(connectionData, targetPane)
                        ? 'connect'
                        : 'rejected';
                }

                deps.openReview(profileId, targetPane, mode);
                return 'review';
            },
        };
    }

    return { createConnectionLauncher };
}));
