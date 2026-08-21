(function (root, factory) {
    const api = factory(root);
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (root) {
        root.WebSSH2Shell = api;
    }
}(typeof window !== 'undefined' ? window : globalThis, function (root) {
    'use strict';

    function buildSessionContext(session) {
        if (!session) {
            return {
                connected: false,
                title: 'No active session',
                host: '—',
                user: '—',
                trust: 'No connected host',
                persistence: 'Not active',
                transport: 'SSH'
            };
        }
        const connected = Boolean(session.connected);
        return {
            connected,
            title: session.displayName
                || [session.username, session.host].filter(Boolean).join('@')
                || 'SSH session',
            host: session.host
                ? `${session.host}:${session.port || 22}`
                : '—',
            user: session.username || '—',
            trust: connected
                ? (session.hostKeyVerified
                    ? 'Host key verified'
                    : 'Verification unavailable')
                : 'Awaiting reconnect',
            persistence: session.useTmux
                ? `tmux${session.tmuxSessionName ? ` · ${session.tmuxSessionName}` : ''}`
                : 'Standard session',
            transport: session.viaJump
                ? `SSH via ${session.viaJump}`
                : 'SSH'
        };
    }

    function init(options) {
        const settings = options || {};
        const documentRef = settings.document || root.document;
        const sessionManager = settings.sessionManager || root.SessionManager;
        if (!documentRef || !sessionManager) { return null; }

        const elements = {
            statusState: documentRef.getElementById('workspaceStatusState'),
            statusTarget: documentRef.getElementById('workspaceStatusTarget'),
            statusTransport: documentRef.getElementById('workspaceStatusTransport'),
            statusTrust: documentRef.getElementById('workspaceStatusTrust'),
            statusPersistence: documentRef.getElementById('workspaceStatusPersistence')
        };

        function render() {
            const activeId = sessionManager.getActiveSession?.();
            const session = activeId
                ? sessionManager.getSession?.(activeId)
                : null;
            const context = buildSessionContext(session);
            if (elements.statusState) {
                elements.statusState.textContent = context.connected ? 'Connected' : 'No active session';
                elements.statusState.classList.toggle('connected', context.connected);
            }
            if (elements.statusTarget) elements.statusTarget.textContent = context.host;
            if (elements.statusTransport) elements.statusTransport.textContent = context.transport;
            if (elements.statusTrust) elements.statusTrust.textContent = context.trust;
            if (elements.statusPersistence) elements.statusPersistence.textContent = context.persistence;
            return context;
        }

        root.addEventListener?.('session-workspace-change', render);
        root.addEventListener?.('session-removed', render);
        render();
        return Object.freeze({ render });
    }

    return Object.freeze({ buildSessionContext, init });
}));
