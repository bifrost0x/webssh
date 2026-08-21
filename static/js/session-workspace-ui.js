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
            filesStatus: documentRef.getElementById('sessionFilesStatus'),
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

        function selectedContext() {
            return root.workspaceLayoutController?.getState?.().activeContext || null;
        }

        function syncInsightsVisibility() {
            coordinator.setVisible(
                documentRef.visibilityState !== 'hidden'
                && selectedContext() === 'diagnostics'
                && diagnosticsController?.isOpen()
            );
        }

        function syncContextControllers(activeContext = selectedContext()) {
            if (activeContext === 'files') coordinator?.openSftpPanel?.();
            diagnosticsController?.setOpen(activeContext === 'diagnostics');
            if (coordinator) syncInsightsVisibility();
        }

        function applySessionContextDefault(state = coordinator?.getState?.()) {
            const session = state?.sessionId
                ? sessionManager.getSession(state.sessionId)
                : null;
            if (!session?.connected || session.restored === true) return false;
            let sftpAvailable = null;
            if (state.sftpCapability === 'available') sftpAvailable = true;
            if (['unavailable', 'inconclusive'].includes(state.sftpCapability)) {
                sftpAvailable = false;
            }
            return root.workspaceLayoutController?.selectSessionDefault?.({
                sessionId: state.sessionId,
                sftpAvailable,
            }) || false;
        }

        function renderInsights(state) {
            lastInsightsState = state;
            const active = sessionManager.getSession(state.sessionId);
            diagnosticsController?.render(state, active, lastInventoryState);
            applySessionContextDefault();
            syncContextControllers();
        }

        filesController = filesModule.createController({
            manager: fileManager,
            container: elements.filesMount,
            status: elements.filesStatus,
            translate(key, fallback) {
                return root.i18n?.t?.(key) || fallback;
            },
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
                // Render the coordinator snapshot before availability changes can
                // synchronously activate Files and trigger a nested, newer render.
                // Otherwise the stale outer snapshot can hide an already-mounted
                // SFTP workspace until the user changes tabs.
                elements.filesPanel.classList.toggle('hidden', !state.filesAvailable);
                root.workspaceLayoutController?.setContextAvailability?.(
                    'files', state.filesAvailable
                );
                sftpCapabilityTracker.probeIfNeeded(state);
                applySessionContextDefault(state);
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
            syncContextControllers();
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
            syncContextControllers(event.detail?.activeContext || null);
        });
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
        syncContextControllers();
        sync();
        return coordinator;
    }

    root.SessionWorkspaceUI = { init };
}(window));
