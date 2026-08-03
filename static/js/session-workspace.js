(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (root && root.document) {
        root.SessionWorkspaceModule = api;
    }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    'use strict';

    function createCoordinator(options) {
        const filesPanel = options.filesPanel;
        const insights = options.insights || {};
        const render = options.render || (() => {});
        const isDesktop = options.isDesktop || (() => true);

        let layout = 1;
        let sessionId = null;
        let session = null;
        let sftpOpen = false;
        let visible = true;

        function canOpenSftp() {
            return Boolean(
                layout === 1
                && isDesktop()
                && sessionId
                && session?.connected
            );
        }

        function state() {
            return {
                layout,
                sessionId,
                connected: Boolean(session?.connected),
                sftpOpen,
                sftpEnabled: canOpenSftp(),
                visible,
            };
        }

        function renderState() {
            render(state());
        }

        function closeSftp() {
            if (!sftpOpen) return;
            sftpOpen = false;
            filesPanel?.close?.();
        }

        return {
            update(next) {
                const previousSessionId = sessionId;
                const wasConnected = Boolean(session?.connected);
                layout = [1, 2, 4].includes(next?.layout) ? next.layout : 1;
                sessionId = typeof next?.sessionId === 'string' && next.sessionId
                    ? next.sessionId
                    : null;
                session = next?.session || null;
                const connected = Boolean(sessionId && session?.connected);
                const sessionChanged = sessionId !== previousSessionId;
                const connectionChanged = connected !== wasConnected;

                if (sessionChanged || connectionChanged) {
                    insights.setSession?.(sessionId, connected);
                }

                if (layout !== 1 || !isDesktop() || !connected) {
                    if (sftpOpen && !connected && sessionId) {
                        filesPanel?.setDisconnected?.(sessionId);
                    }
                    closeSftp();
                } else if (sftpOpen && sessionChanged) {
                    filesPanel?.follow?.(sessionId, session);
                }

                renderState();
            },

            toggleSftp() {
                if (sftpOpen) {
                    closeSftp();
                    renderState();
                    return false;
                }
                if (!canOpenSftp()) {
                    renderState();
                    return false;
                }
                sftpOpen = true;
                filesPanel?.open?.(sessionId, session);
                renderState();
                return true;
            },

            setVisible(nextVisible) {
                visible = Boolean(nextVisible);
                insights.setVisible?.(visible);
                renderState();
            },

            getState() {
                return state();
            },
        };
    }

    return { createCoordinator };
}));
