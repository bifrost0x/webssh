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
                persistence: t('workspace.notActive', 'Not active'),
                transport: ''
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
            persistence: session.useTmux
                ? `tmux${session.tmuxSessionName ? ` · ${session.tmuxSessionName}` : ''}`
                : t('workspace.standardSession', 'Standard session'),
            transport: session.viaJump
                ? `SSH ${t('connection.via', 'via')} ${session.viaJump}`
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
            statusUser: documentRef.getElementById('workspaceStatusUser'),
            statusUserField: documentRef.getElementById('workspaceStatusUserField'),
            transfers: documentRef.getElementById('workspaceStatusTransfers'),
            transferCount: documentRef.getElementById('workspaceStatusTransferCount'),
            statusPersistence: documentRef.getElementById('workspaceStatusPersistence')
        };

        function render() {
            const activeId = sessionManager.getWorkspaceSession?.()
                || sessionManager.getActiveSession?.();
            const session = activeId
                ? sessionManager.getSession?.(activeId)
                : null;
            const context = buildSessionContext(session, translate);
            // A retained SSH session is not currently reachable while the browser
            // transport reconnects. Keep its endpoint, but do not show green.
            const transportReady = root.socket?.connected !== false;
            context.connected = context.connected && transportReady;
            if (elements.statusState) {
                elements.statusState.textContent = context.connected
                    ? (translate('workspace.connected') || 'Connected')
                    : session
                        ? (translate(transportReady ? 'session.disconnected' : 'connection.lostReconnecting'))
                        : context.title;
                elements.statusState.classList.toggle('connected', context.connected);
            }
            if (elements.statusTarget) elements.statusTarget.textContent = context.host;
            if (elements.statusTransport) elements.statusTransport.textContent = context.transport;
            if (elements.statusUser) elements.statusUser.textContent = session?.username || '';
            if (elements.statusUserField) elements.statusUserField.hidden = !session?.username;
            if (elements.statusTarget?.parentElement) elements.statusTarget.parentElement.hidden = !session?.host;
            if (elements.statusTransport) elements.statusTransport.hidden = !session;
            if (elements.statusPersistence) elements.statusPersistence.hidden = !session;
            if (elements.statusPersistence) elements.statusPersistence.textContent = context.persistence;
            return context;
        }

        function renderTransfers() {
            const queue = root.sftpFileManager?.transferQueue || [];
            if (elements.transferCount) elements.transferCount.textContent = String(queue.length);
        }
        elements.transfers?.addEventListener('click', () => {
            documentRef.getElementById('fileTransferBtn')?.click();
            if (documentRef.getElementById('fmQueue')?.classList.contains('collapsed')) {
                root.sftpFileManager?.toggleQueue();
            }
        });
        root.addEventListener?.('file-transfer-queue-change', renderTransfers);
        root.socket?.on('connect', render);
        root.socket?.on('disconnect', render);
        renderTransfers();
        root.addEventListener?.('session-workspace-change', render);
        root.addEventListener?.('session-removed', render);
        root.addEventListener?.('languageChanged', render);
        render();
        return Object.freeze({ render });
    }

    return Object.freeze({ buildSessionContext, init });
}));
