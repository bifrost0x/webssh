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

    function createSftpCapabilityTracker(options) {
        const socket = options.socket;
        const onChange = options.onChange || (() => {});
        const setTimeoutFn = options.setTimeoutFn || setTimeout;
        const clearTimeoutFn = options.clearTimeoutFn || clearTimeout;
        let requestSequence = 0;
        const createRequestId = options.createRequestId || (() => (
            `sftp:${Date.now().toString(36)}:${++requestSequence}`
        ));
        const capabilities = new Map();
        const pending = new Map();
        const retryTimers = new Map();
        const retryCounts = new Map();
        let activeProbeSessionId = null;

        function clearRetry(sessionId) {
            const timerId = retryTimers.get(sessionId);
            if (timerId !== undefined) clearTimeoutFn(timerId);
            retryTimers.delete(sessionId);
        }

        function startProbe(sessionId) {
            if (pending.has(sessionId) || capabilities.has(sessionId)) return false;
            const requestId = createRequestId();
            const timeoutId = setTimeoutFn(() => {
                const request = pending.get(sessionId);
                if (!request || request.requestId !== requestId) return;
                pending.delete(sessionId);
                scheduleRetry(sessionId);
            }, 5000);
            pending.set(sessionId, { requestId, timeoutId });
            socket.emit('probe_session_sftp', {
                session_id: sessionId,
                request_id: requestId,
            });
            return true;
        }

        function scheduleRetry(sessionId) {
            const retries = retryCounts.get(sessionId) || 0;
            if (retries >= 2 && activeProbeSessionId === sessionId) {
                clearRetry(sessionId);
                retryCounts.delete(sessionId);
                capabilities.set(sessionId, 'inconclusive');
                onChange(sessionId);
                return;
            }
            if (
                retryTimers.has(sessionId)
                || activeProbeSessionId !== sessionId
            ) return;
            retryCounts.set(sessionId, retries + 1);
            const timerId = setTimeoutFn(() => {
                retryTimers.delete(sessionId);
                if (activeProbeSessionId === sessionId) startProbe(sessionId);
            }, 10000);
            retryTimers.set(sessionId, timerId);
        }

        socket.on('session_sftp_capability', data => {
            const sessionId = typeof data?.session_id === 'string'
                ? data.session_id
                : '';
            const requestId = typeof data?.request_id === 'string'
                ? data.request_id
                : '';
            const request = pending.get(sessionId);
            if (!sessionId || !request || request.requestId !== requestId) return;
            clearTimeoutFn(request.timeoutId);
            pending.delete(sessionId);
            if (data.success !== true) {
                scheduleRetry(sessionId);
                return;
            }
            clearRetry(sessionId);
            retryCounts.delete(sessionId);
            capabilities.set(
                sessionId,
                data.available === true ? 'available' : 'unavailable'
            );
            onChange(sessionId);
        });

        return {
            get(sessionId) {
                if (capabilities.has(sessionId)) return capabilities.get(sessionId);
                if (pending.has(sessionId) || retryTimers.has(sessionId)) return 'probing';
                return 'unknown';
            },

            probeIfNeeded(state) {
                const targetSessionId = state?.sessionId;
                const eligibleSessionId = (
                    state?.sftpProbeNeeded
                    || state?.sftpCapability === 'probing'
                )
                    && typeof targetSessionId === 'string'
                    && targetSessionId
                    ? targetSessionId
                    : null;
                if (activeProbeSessionId !== eligibleSessionId) {
                    if (activeProbeSessionId) clearRetry(activeProbeSessionId);
                    activeProbeSessionId = eligibleSessionId;
                }
                if (
                    !eligibleSessionId
                    || pending.has(targetSessionId)
                    || retryTimers.has(targetSessionId)
                ) {
                    return false;
                }
                return startProbe(targetSessionId);
            },

            remove(sessionId) {
                clearRetry(sessionId);
                capabilities.delete(sessionId);
                const request = pending.get(sessionId);
                if (request) clearTimeoutFn(request.timeoutId);
                pending.delete(sessionId);
                retryCounts.delete(sessionId);
                if (activeProbeSessionId === sessionId) activeProbeSessionId = null;
            },
        };
    }

    function createCoordinator(options) {
        const filesPanel = options.filesPanel;
        const insights = options.insights || {};
        const render = options.render || (() => {});
        const isDesktop = options.isDesktop || (() => true);
        const isWideDesktop = options.isWideDesktop || (() => false);

        let layout = 1;
        let sessionId = null;
        let session = null;
        let sftpOpen = false;
        let panelSessionId = null;
        let sftpCapability = 'unknown';
        let visible = true;
        const sftpPreferences = new Map();

        function canOpenSftp() {
            return Boolean(
                layout === 1
                && isDesktop()
                && sessionId
                && session?.connected
                && ['available', 'inconclusive'].includes(sftpCapability)
            );
        }

        function shouldOpenSftp() {
            if (!canOpenSftp()) return false;
            const preference = sftpPreferences.get(sessionId);
            if (preference === 'open') return true;
            if (preference === 'closed') return false;
            return isWideDesktop() && sftpCapability === 'available';
        }

        function state() {
            const sftpProbeNeeded = Boolean(
                layout === 1
                && isDesktop()
                && sessionId
                && session?.connected
                && sftpCapability === 'unknown'
            );
            return {
                layout,
                sessionId,
                connected: Boolean(session?.connected),
                sftpOpen,
                sftpEnabled: canOpenSftp(),
                sftpCapability,
                sftpProbeNeeded,
                visible,
            };
        }

        function renderState() {
            render(state());
        }

        function closeSftp() {
            if (!sftpOpen) return;
            sftpOpen = false;
            panelSessionId = null;
            filesPanel?.close?.();
        }

        function openSftp() {
            sftpOpen = true;
            panelSessionId = sessionId;
            filesPanel?.open?.(sessionId, session);
        }

        return {
            update(next) {
                const previousSessionId = sessionId;
                const wasConnected = Boolean(session?.connected);
                const previousLayout = layout;
                layout = [1, 2, 4].includes(next?.layout) ? next.layout : 1;
                sessionId = typeof next?.sessionId === 'string' && next.sessionId
                    ? next.sessionId
                    : null;
                session = next?.session || null;
                sftpCapability = [
                    'available',
                    'unavailable',
                    'probing',
                    'inconclusive',
                ].includes(next?.sftpCapability)
                    ? next.sftpCapability
                    : 'unknown';
                const connected = Boolean(sessionId && session?.connected);
                const sessionChanged = sessionId !== previousSessionId;
                const connectionChanged = connected !== wasConnected;

                if (sessionChanged || connectionChanged) {
                    insights.setSession?.(sessionId, connected);
                }

                if (previousLayout === 1 && layout !== 1 && previousSessionId) {
                    sftpPreferences.set(previousSessionId, 'closed');
                }
                if (layout !== 1 || !isDesktop() || !connected) {
                    if (sftpOpen && !connected && sessionId) {
                        filesPanel?.setDisconnected?.(sessionId);
                    }
                    closeSftp();
                } else if (shouldOpenSftp()) {
                    if (sftpOpen && panelSessionId !== sessionId) {
                        panelSessionId = sessionId;
                        filesPanel?.follow?.(sessionId, session);
                    } else if (!sftpOpen) {
                        openSftp();
                    }
                } else {
                    closeSftp();
                }

                renderState();
            },

            toggleSftp() {
                if (sftpOpen) {
                    if (sessionId) sftpPreferences.set(sessionId, 'closed');
                    closeSftp();
                    renderState();
                    return false;
                }
                if (!canOpenSftp()) {
                    renderState();
                    return false;
                }
                sftpPreferences.set(sessionId, 'open');
                openSftp();
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

    return { createCoordinator, createSftpCapabilityTracker };
}));
