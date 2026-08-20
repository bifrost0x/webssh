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

    function toolAction(tool) {
        return ({
            files: 'sessionSftpToggleBtn',
            commands: 'commandLibraryBtn',
            diagnostics: 'sessionDiagnosticsToggle',
            notes: 'notepadToggle'
        })[tool] || null;
    }

    function init(options) {
        const settings = options || {};
        const documentRef = settings.document || root.document;
        const sessionManager = settings.sessionManager || root.SessionManager;
        if (!documentRef || !sessionManager) { return null; }

        const elements = {
            title: documentRef.getElementById('sessionContextTitle'),
            state: documentRef.getElementById('sessionContextState'),
            host: documentRef.getElementById('sessionContextHost'),
            user: documentRef.getElementById('sessionContextUser'),
            trust: documentRef.getElementById('sessionContextTrust'),
            persistence: documentRef.getElementById('sessionContextPersistence'),
            statusState: documentRef.getElementById('workspaceStatusState'),
            statusTarget: documentRef.getElementById('workspaceStatusTarget'),
            statusTransport: documentRef.getElementById('workspaceStatusTransport'),
            statusTrust: documentRef.getElementById('workspaceStatusTrust'),
            statusPersistence: documentRef.getElementById('workspaceStatusPersistence'),
            tabs: documentRef.getElementById('sessionToolTabs')
        };

        function render() {
            const activeId = sessionManager.getActiveSession?.();
            const session = activeId
                ? sessionManager.getSession?.(activeId)
                : null;
            const context = buildSessionContext(session);
            if (elements.title) elements.title.textContent = context.title;
            if (elements.state) {
                elements.state.textContent = context.connected ? 'Connected' : 'Offline';
                elements.state.classList.toggle('connected', context.connected);
            }
            if (elements.host) elements.host.textContent = context.host;
            if (elements.user) elements.user.textContent = context.user;
            if (elements.trust) elements.trust.textContent = context.trust;
            if (elements.persistence) elements.persistence.textContent = context.persistence;
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

        elements.tabs?.addEventListener('click', event => {
            const button = event.target.closest('[data-session-tool]');
            if (!button) { return; }
            const tool = button.dataset.sessionTool;
            const control = documentRef.getElementById(toolAction(tool));
            if (!control || control.disabled) { return; }
            const notesPanel = documentRef.getElementById('notepadPanel');
            if (tool !== 'notes' || notesPanel?.classList.contains('collapsed')) {
                control.click();
            }
            for (const tab of elements.tabs.querySelectorAll('[data-session-tool]')) {
                const active = tab === button;
                tab.classList.toggle('active', active);
                tab.setAttribute('aria-pressed', String(active));
            }
            if (tool === 'notes') {
                documentRef.getElementById('sessionNotepad')?.focus();
            }
        });

        root.addEventListener?.('session-workspace-change', render);
        root.addEventListener?.('session-removed', render);
        render();
        return Object.freeze({ render });
    }

    return Object.freeze({ buildSessionContext, init, toolAction });
}));
