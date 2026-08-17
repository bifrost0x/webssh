(function (root) {
    'use strict';

    function formatUptime(seconds) {
        const total = Number(seconds);
        if (!Number.isFinite(total) || total < 0) return 'Uptime --';
        const days = Math.floor(total / 86400);
        const hours = Math.floor((total % 86400) / 3600);
        if (days > 0) return `Uptime ${days}d ${hours}h`;
        const minutes = Math.floor((total % 3600) / 60);
        return `Uptime ${hours}h ${minutes}m`;
    }

    function percent(used, total) {
        const usedValue = Number(used);
        const totalValue = Number(total);
        if (!Number.isFinite(usedValue) || !Number.isFinite(totalValue) || totalValue <= 0) {
            return 0;
        }
        return Math.max(0, Math.min(100, Math.round((usedValue / totalValue) * 100)));
    }

    function drawCpuHistory(canvas, history) {
        if (!canvas) return;
        const context = canvas.getContext('2d');
        if (!context) return;
        const width = canvas.width;
        const height = canvas.height;
        context.clearRect(0, 0, width, height);

        const styles = getComputedStyle(canvas);
        const lineColor = styles.getPropertyValue('--accent-primary').trim() || '#58a6ff';
        const gridColor = styles.getPropertyValue('--border-color').trim() || 'rgba(127,127,127,.25)';
        context.strokeStyle = gridColor;
        context.lineWidth = 1;
        [0.25, 0.5, 0.75].forEach(ratio => {
            context.beginPath();
            context.moveTo(0, Math.round(height * ratio) + 0.5);
            context.lineTo(width, Math.round(height * ratio) + 0.5);
            context.stroke();
        });

        const values = Array.isArray(history) ? history : [];
        if (values.length < 2) return;
        context.strokeStyle = lineColor;
        context.lineWidth = 2;
        context.lineJoin = 'round';
        context.lineCap = 'round';
        context.beginPath();
        values.forEach((value, index) => {
            const x = (index / (values.length - 1)) * (width - 4) + 2;
            const y = height - ((Math.max(0, Math.min(100, value)) / 100) * (height - 8)) - 4;
            if (index === 0) context.moveTo(x, y);
            else context.lineTo(x, y);
        });
        context.stroke();
    }

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
            mainSplit: documentRef.getElementById('sessionMainSplit'),
            filesPanel: documentRef.getElementById('sessionFilesPanel'),
            toggle: documentRef.getElementById('sessionSftpToggleBtn'),
            filesMount: documentRef.getElementById('sessionFilesMount'),
            notepadPanel: documentRef.getElementById('notepadPanel'),
            insightsCard: documentRef.getElementById('sessionInsightsCard'),
            insightsHost: documentRef.getElementById('sessionInsightsHost'),
            insightsState: documentRef.getElementById('sessionInsightsState'),
            cpuResource: documentRef.getElementById('sessionCpuResource'),
            cpuGauge: documentRef.getElementById('sessionCpuGauge'),
            cpuValue: documentRef.getElementById('sessionCpuValue'),
            cpuChart: documentRef.getElementById('sessionCpuChart'),
            ramResource: documentRef.getElementById('sessionRamResource'),
            ramValue: documentRef.getElementById('sessionRamValue'),
            ramBar: documentRef.getElementById('sessionRamBar'),
            diskResource: documentRef.getElementById('sessionDiskResource'),
            diskValue: documentRef.getElementById('sessionDiskValue'),
            diskBar: documentRef.getElementById('sessionDiskBar'),
            osValue: documentRef.getElementById('sessionOsValue'),
            uptimeValue: documentRef.getElementById('sessionUptimeValue'),
            insightsMeta: documentRef.getElementById('sessionInsightsMeta'),
        };
        if (!elements.mainSplit || !elements.toggle || !elements.filesPanel || !elements.filesMount) return null;

        let filesController = null;
        let coordinator = null;
        let insightsController = null;
        let inventoryController = null;
        let diagnosticsController = null;
        let lastInsightsState = { status: 'disconnected', sessionId: null };
        let lastInventoryState = { status: 'disconnected', sessionId: null, inventory: null };
        let inventorySessionId = null;
        let inventoryConnected = false;

        function setResource(element, bar, value) {
            const severity = insightsModule.severityForPercent(value);
            element.classList.remove('normal', 'warning', 'critical');
            element.classList.add(severity);
            bar.style.width = `${value}%`;
        }

        function renderInsights(state) {
            lastInsightsState = state;
            const active = sessionManager.getSession(state.sessionId);
            const availability = insightsModule.metricAvailability(state);
            diagnosticsController?.render(state, active, lastInventoryState);
            elements.insightsCard.hidden = !availability.any;
            elements.cpuResource.hidden = !availability.cpu;
            elements.ramResource.hidden = !availability.memory;
            elements.diskResource.hidden = !availability.disk;
            elements.osValue.hidden = !availability.os;
            elements.uptimeValue.hidden = !availability.uptime;
            elements.insightsMeta.hidden = !availability.os && !availability.uptime;
            if (!availability.any) {
                drawCpuHistory(elements.cpuChart, []);
                return;
            }

            elements.insightsHost.textContent = active
                ? `${active.username}@${active.host}`
                : 'No active session';
            const labels = {
                ready: 'Live', loading: 'Sampling', stale: 'Stale',
                unavailable: 'Unavailable', disconnected: 'Offline',
            };
            elements.insightsState.textContent = labels[state.status] || 'Offline';
            elements.insightsState.className = `session-insights-state ${state.status || ''}`;

            if (availability.cpu) {
                const cpu = state.cpuPercent;
                elements.cpuValue.textContent = `${cpu}%`;
                elements.cpuGauge.style.setProperty('--value', String(cpu));
                elements.cpuGauge.classList.remove('normal', 'warning', 'critical');
                elements.cpuGauge.classList.add(insightsModule.severityForPercent(cpu));
                drawCpuHistory(elements.cpuChart, state.cpuHistory);
            } else {
                drawCpuHistory(elements.cpuChart, []);
            }

            if (availability.memory) {
                const memoryPercent = percent(
                    state.stats.memory.used_kib,
                    state.stats.memory.total_kib,
                );
                elements.ramValue.textContent = `${insightsModule.formatKib(state.stats.memory.used_kib)} / ${insightsModule.formatKib(state.stats.memory.total_kib)}`;
                setResource(elements.ramResource, elements.ramBar, memoryPercent);
            }
            if (availability.disk) {
                const diskPercent = Number(state.stats.disk.percent);
                elements.diskValue.textContent = `${insightsModule.formatKib(state.stats.disk.used_kib)} / ${insightsModule.formatKib(state.stats.disk.total_kib)}`;
                setResource(elements.diskResource, elements.diskBar, diskPercent);
            }
            if (availability.os) elements.osValue.textContent = state.stats.os_name;
            if (availability.uptime) {
                elements.uptimeValue.textContent = formatUptime(state.stats.uptime_seconds);
            }
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
        const desktopQuery = root.matchMedia('(min-width: 851px)');
        const wideDesktopQuery = root.matchMedia('(min-width: 1440px)');
        const sftpCapabilityTracker = workspaceModule.createSftpCapabilityTracker({
            socket,
            onChange: sync,
        });
        coordinator = workspaceModule.createCoordinator({
            filesPanel: filesController,
            insights: insightsController,
            isDesktop: () => desktopQuery.matches,
            isWideDesktop: () => wideDesktopQuery.matches,
            render(state) {
                elements.toggle.disabled = !state.sftpEnabled;
                elements.toggle.setAttribute('aria-pressed', String(state.sftpOpen));
                elements.mainSplit.classList.toggle('sftp-open', state.sftpOpen);
                elements.filesPanel.classList.toggle('hidden', !state.sftpOpen);
                sftpCapabilityTracker.probeIfNeeded(state);
                root.requestAnimationFrame(() => terminalManager?.fitAllTerminals?.());
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

        elements.toggle.addEventListener('click', () => coordinator.toggleSftp());
        documentRef.getElementById('sessionFilesCloseBtn')?.addEventListener('click', () => coordinator.toggleSftp());
        root.addEventListener('session-sftp-request-close', () => {
            if (coordinator.getState().sftpOpen) coordinator.toggleSftp();
        });

        function syncInsightsVisibility() {
            coordinator.setVisible(
                documentRef.visibilityState !== 'hidden'
                && (
                    diagnosticsController?.isOpen()
                    || (
                        desktopQuery.matches
                        && !elements.notepadPanel?.classList.contains('collapsed')
                    )
                )
            );
        }
        root.addEventListener('session-workspace-change', sync);
        root.addEventListener('session-removed', event => {
            const removedSessionId = event?.detail?.sessionId;
            insightsController?.removeSession(removedSessionId);
            inventoryController?.removeSession(removedSessionId);
            sftpCapabilityTracker.remove(removedSessionId);
        });
        documentRef.addEventListener('visibilitychange', syncInsightsVisibility);
        desktopQuery.addEventListener?.('change', () => {
            syncInsightsVisibility();
            sync();
        });
        wideDesktopQuery.addEventListener?.('change', sync);
        if (elements.notepadPanel && root.MutationObserver) {
            new MutationObserver(syncInsightsVisibility).observe(elements.notepadPanel, {
                attributes: true,
                attributeFilter: ['class'],
            });
        }
        root.addEventListener('themeChanged', () => {
            drawCpuHistory(elements.cpuChart, lastInsightsState.cpuHistory || []);
            diagnosticsController?.redraw();
        });
        syncInsightsVisibility();
        sync();
        return coordinator;
    }

    root.SessionWorkspaceUI = { init, formatUptime };
}(window));
