(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (root && root.document) {
        root.AccountWorkspacePulseModule = api;
    }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    'use strict';

    function getWorkspacePulseState(sessionManager) {
        const sessions = sessionManager?.getAllSessions?.()
            || Object.values(sessionManager?.sessions || {});
        const activeSessionId = sessionManager?.getActiveSession?.()
            || sessionManager?.activeSessionId
            || null;
        const activeSession = activeSessionId
            ? (sessionManager?.getSession?.(activeSessionId) || sessionManager?.sessions?.[activeSessionId])
            : null;

        return {
            connectedSessions: sessions.filter(session => session?.connected).length,
            occupiedPanes: (sessionManager?.paneAssignments || []).filter(Boolean).length,
            currentLabel: activeSession
                ? (activeSession.displayName || `${activeSession.username}@${activeSession.host}`)
                : null,
            currentConnected: Boolean(activeSession?.connected),
        };
    }

    function createAccountWorkspacePulse(options) {
        const sessionManager = options?.sessionManager;
        const documentRef = options?.document;
        const windowRef = options?.window;
        const translate = options?.translate || (key => key);
        let elements = null;

        function render() {
            if (!elements) return false;
            const state = getWorkspacePulseState(sessionManager);
            elements.sessions.textContent = String(state.connectedSessions);
            elements.panes.textContent = String(state.occupiedPanes);
            elements.current.textContent = state.currentLabel || translate('account.noActiveSession');
            elements.status.classList.toggle('is-connected', state.currentConnected);
            elements.status.classList.toggle('is-offline', !state.currentConnected);
            elements.status.title = translate(
                state.currentConnected ? 'account.connected' : 'account.offline'
            );
            elements.root.dataset.connectionState = state.currentConnected ? 'connected' : 'offline';
            return true;
        }

        function init() {
            elements = {
                root: documentRef?.getElementById('accountWorkspacePulse'),
                sessions: documentRef?.getElementById('accountPulseSessions'),
                panes: documentRef?.getElementById('accountPulsePanes'),
                current: documentRef?.getElementById('accountPulseCurrent'),
                status: documentRef?.getElementById('accountPulseStatus'),
            };
            if (Object.values(elements).some(element => !element)) {
                elements = null;
                return false;
            }
            windowRef?.addEventListener('session-workspace-change', render);
            windowRef?.addEventListener('languageChanged', render);
            return render();
        }

        function destroy() {
            windowRef?.removeEventListener('session-workspace-change', render);
            windowRef?.removeEventListener('languageChanged', render);
            elements = null;
        }

        return { init, render, destroy };
    }

    return { createAccountWorkspacePulse, getWorkspacePulseState };
}));
