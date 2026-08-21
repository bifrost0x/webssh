(function (root) {
    'use strict';

    function init(options) {
        const socket = options.socket;
        const sessionManager = options.sessionManager;
        const terminalManager = options.terminalManager;
        const documentRef = options.document || document;
        const insightsModule = root.SessionInsightsModule;
        const diagnosticsModule = root.SessionDiagnosticsModule;
        const inventoryModule = root.SessionRuntimeInventoryModule;
        const chartsModule = root.SessionDiagnosticsCharts;
        const filesModule = root.SessionFilesPanelModule;
        const workspaceModule = root.SessionWorkspaceModule;
        const fileManager = root.getSFTPFileManager?.();
        if (!socket || !sessionManager || !insightsModule || !diagnosticsModule || !inventoryModule || !chartsModule || !filesModule || !workspaceModule || !fileManager) {
            return null;
        }

        const elements = {
            filesPanel: documentRef.getElementById('sessionFilesPanel'),
            filesTab: documentRef.getElementById('contextFilesTab'),
            filesMount: documentRef.getElementById('sessionFilesMount'),
        };
        if (!elements.filesTab || !elements.filesPanel || !elements.filesMount) return null;

        let filesController = null;
        let coordinator = null;
        let insightsController = null;
        let inventoryController = null;
        let diagnosticsController = null;
        let lastInsightsState = { status: 'disconnected', sessionId: null };
        let lastInventoryState = { status: 'disconnected', sessionId: null, inventory: null };
        let inventorySessionId = null;
        let inventoryConnected = false;

        function renderInsights(state) {
            lastInsightsState = state;
            const active = sessionManager.getSession(state.sessionId);
            diagnosticsController?.render(state, active, lastInventoryState);
        }

        filesController = filesModule.createController({
            manager: fileManager,
            container: elements.filesMount,
        });
        diagnosticsController = diagnosticsModule.createController({
            document: documentRef,
            window: root,
            inventoryModule,
            chartModule: chartsModule,
            onRefreshInventory() {
                inventoryController?.refresh();
            },
            onOpenChange(open) {
                insightsController?.setDiagnosticsVisible(open);
                inventoryController?.setOpen(open);
                syncInsightsVisibility();
            },
        });
        inventoryController = inventoryModule.createController({
            socket,
            render(state) {
                lastInventoryState = state;
                const active = sessionManager.getSession(lastInsightsState.sessionId);
                diagnosticsController?.render(lastInsightsState, active, lastInventoryState);
            },
        });
        insightsController = insightsModule.createController({ socket, render: renderInsights });
        const wideDesktopQuery = root.matchMedia('(min-width: 1440px)');
        const sftpCapabilityTracker = workspaceModule.createSftpCapabilityTracker({
            socket,
            onChange: sync,
        });
        coordinator = workspaceModule.createCoordinator({
            filesPanel: filesController,
            insights: insightsController,
            isWideDesktop: () => wideDesktopQuery.matches,
            render(state) {
                root.workspaceLayoutController?.setContextAvailability?.(
                    'files', state.sftpEnabled
                );
                elements.filesPanel.classList.toggle('hidden', !state.sftpOpen);
                sftpCapabilityTracker.probeIfNeeded(state);
                root.requestAnimationFrame(() => {
                    terminalManager?.fitAndSyncVisibleTerminals?.({
                        socket,
                        isConnected: sessionId => Boolean(
                            sessionManager.getSession(sessionId)?.connected
                        ),
                        force: true,
                    });
                });
            },
        });

        function sync() {
            const activeId = sessionManager.getActiveSession();
            const activeSession = activeId ? sessionManager.getSession(activeId) : null;
            const connected = Boolean(activeId && activeSession?.connected);
            coordinator.update({
                layout: sessionManager.layout,
                sessionId: activeId,
                session: activeSession,
                sessionCount: sessionManager.getAllSessions().length,
                sftpCapability: sftpCapabilityTracker.get(activeId),
            });
            if (activeId !== inventorySessionId || connected !== inventoryConnected) {
                inventorySessionId = activeId || null;
                inventoryConnected = connected;
                inventoryController.setSession(inventorySessionId, inventoryConnected);
            }
        }

        documentRef.addEventListener('session-sftp-request-close', () => {
            if (coordinator.getState().sftpOpen) coordinator.toggleSftp();
            if (root.workspaceLayoutController?.getState?.().activeContext === 'files') {
                root.workspaceLayoutController.closeContext('programmatic');
            }
        });

        documentRef.addEventListener('workspace-context-change', event => {
            const activeContext = event.detail?.activeContext || null;
            if (activeContext === 'files') coordinator.openSftpPanel();
            diagnosticsController?.setOpen(activeContext === 'diagnostics');
            syncInsightsVisibility();
        });

        function syncInsightsVisibility() {
            coordinator.setVisible(
                documentRef.visibilityState !== 'hidden'
                && root.workspaceLayoutController?.getState?.().activeContext === 'diagnostics'
                && diagnosticsController?.isOpen()
            );
        }
        root.addEventListener('session-workspace-change', sync);
        root.addEventListener('session-removed', event => {
            const removedSessionId = event?.detail?.sessionId;
            insightsController?.removeSession(removedSessionId);
            inventoryController?.removeSession(removedSessionId);
            sftpCapabilityTracker.remove(removedSessionId);
            coordinator.removeSession(removedSessionId);
        });
        documentRef.addEventListener('visibilitychange', syncInsightsVisibility);
        wideDesktopQuery.addEventListener?.('change', sync);
        root.addEventListener('themeChanged', () => {
            diagnosticsController?.redraw();
        });
        syncInsightsVisibility();
        sync();
        return coordinator;
    }

    root.SessionWorkspaceUI = { init };
}(window));
