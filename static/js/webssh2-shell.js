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

    function buildSessionContext(session, translate) {
        const t = (key, fallback) => {
            const translated = typeof translate === 'function' ? translate(key) : null;
            return translated && translated !== key ? translated : fallback;
        };
        if (!session) {
            return {
                connected: false,
                title: t('workspace.noActiveSession', 'No active session'),
                host: '—',
                user: '—',
                trust: t('workspace.noConnectedHost', 'No connected host'),
                persistence: t('workspace.notActive', 'Not active'),
                transport: 'SSH'
            };
        }
        const connected = Boolean(session.connected);
        return {
            connected,
            title: session.displayName
                || [session.username, session.host].filter(Boolean).join('@')
                || t('workspace.sshSession', 'SSH session'),
            host: session.host
                ? `${session.host}:${session.port || 22}`
                : '—',
            user: session.username || '—',
            trust: connected
                ? (session.hostKeyVerified
                    ? t('workspace.hostKeyVerified', 'Host key verified')
                    : t('workspace.verificationUnavailable', 'Verification unavailable'))
                : t('workspace.awaitingReconnect', 'Awaiting reconnect'),
            persistence: session.useTmux
                ? `tmux${session.tmuxSessionName ? ` · ${session.tmuxSessionName}` : ''}`
                : t('workspace.standardSession', 'Standard session'),
            transport: session.viaJump
                ? `SSH via ${session.viaJump}`
                : 'SSH'
        };
    }

    function init(options) {
        const settings = options || {};
        const documentRef = settings.document || root.document;
        const sessionManager = settings.sessionManager || root.SessionManager;
        const translate = settings.translate || (key => root.i18n?.t?.(key));
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
            const context = buildSessionContext(session, translate);
            if (elements.statusState) {
                elements.statusState.textContent = context.connected
                    ? (translate('workspace.connected') || 'Connected')
                    : context.title;
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
        root.addEventListener?.('languageChanged', render);
        render();
        return Object.freeze({ render });
    }

    return Object.freeze({ buildSessionContext, init });
}));
