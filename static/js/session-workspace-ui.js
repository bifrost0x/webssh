(function (root) {
    'use strict';

    function formatFileSize(bytes) {
        const value = Number(bytes);
        if (!Number.isFinite(value) || value < 0) return '';
        if (value < 1024) return `${value} B`;
        if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
        if (value < 1024 * 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MB`;
        return `${(value / (1024 * 1024 * 1024)).toFixed(1)} GB`;
    }

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
        const filesModule = root.SessionFilesPanelModule;
        const workspaceModule = root.SessionWorkspaceModule;
        if (!socket || !sessionManager || !insightsModule || !filesModule || !workspaceModule) {
            return null;
        }

        const elements = {
            mainSplit: documentRef.getElementById('sessionMainSplit'),
            filesPanel: documentRef.getElementById('sessionFilesPanel'),
            toggle: documentRef.getElementById('sessionSftpToggleBtn'),
            filesHost: documentRef.getElementById('sessionFilesHost'),
            filesPath: documentRef.getElementById('sessionFilesPath'),
            filesStatus: documentRef.getElementById('sessionFilesStatus'),
            filesList: documentRef.getElementById('sessionFilesList'),
            download: documentRef.getElementById('sessionFilesDownloadBtn'),
            rename: documentRef.getElementById('sessionFilesRenameBtn'),
            delete: documentRef.getElementById('sessionFilesDeleteBtn'),
            uploadInput: documentRef.getElementById('sessionFilesUploadInput'),
            notepadPanel: documentRef.getElementById('notepadPanel'),
            insightsHost: documentRef.getElementById('sessionInsightsHost'),
            insightsState: documentRef.getElementById('sessionInsightsState'),
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
        };
        if (!elements.mainSplit || !elements.toggle || !elements.filesPanel) return null;

        let filesController = null;
        let coordinator = null;

        function renderFiles(state) {
            elements.filesPanel.classList.toggle('hidden', !state.open);
            elements.filesHost.textContent = state.label || 'No active session';
            elements.filesPath.textContent = state.path || '/';
            const statusLabels = {
                loading: 'Loading remote directory...',
                ready: `${state.files.length} item${state.files.length === 1 ? '' : 's'}`,
                disconnected: 'SSH session disconnected',
                error: state.error || 'SFTP unavailable',
                closed: '',
            };
            elements.filesStatus.textContent = statusLabels[state.status] || '';
            elements.filesStatus.classList.toggle('error', state.status === 'error');
            elements.filesList.replaceChildren();
            state.files.forEach((item, index) => {
                const row = documentRef.createElement('div');
                row.className = 'session-file-row';
                row.classList.toggle('selected', index === state.selectedIndex);
                row.setAttribute('role', 'option');
                row.setAttribute('aria-selected', String(index === state.selectedIndex));
                row.tabIndex = 0;

                const icon = documentRef.createElement('span');
                icon.className = 'material-icons';
                icon.setAttribute('aria-hidden', 'true');
                icon.textContent = item.is_dir ? 'folder' : 'insert_drive_file';
                const name = documentRef.createElement('span');
                name.className = 'session-file-name';
                name.textContent = item.name || '';
                const size = documentRef.createElement('span');
                size.className = 'session-file-size';
                size.textContent = item.is_dir ? '' : formatFileSize(item.size);
                row.append(icon, name, size);
                row.addEventListener('click', () => filesController.select(index));
                row.addEventListener('dblclick', () => filesController.activate(index));
                row.addEventListener('keydown', event => {
                    if (event.key === 'Enter') filesController.activate(index);
                });
                elements.filesList.appendChild(row);
            });
            const selected = state.files[state.selectedIndex];
            elements.download.disabled = !selected || Boolean(selected.is_dir);
            elements.rename.disabled = !selected;
            elements.delete.disabled = !selected;
        }

        function setResource(element, bar, value) {
            const severity = insightsModule.severityForPercent(value);
            element.classList.remove('normal', 'warning', 'critical');
            element.classList.add(severity);
            bar.style.width = `${value}%`;
        }

        function renderInsights(state) {
            const active = sessionManager.getSession(state.sessionId);
            elements.insightsHost.textContent = active
                ? `${active.username}@${active.host}`
                : 'No active session';
            const labels = {
                ready: 'Live', loading: 'Sampling', stale: 'Stale',
                unavailable: 'Unavailable', disconnected: 'Offline',
            };
            elements.insightsState.textContent = labels[state.status] || 'Offline';
            elements.insightsState.className = `session-insights-state ${state.status || ''}`;
            if (!state.stats) {
                if (state.status === 'disconnected' || state.status === 'unavailable') {
                    elements.cpuValue.textContent = '--';
                    elements.cpuGauge.style.setProperty('--value', '0');
                    elements.ramValue.textContent = '--';
                    elements.diskValue.textContent = '--';
                    elements.ramBar.style.width = '0%';
                    elements.diskBar.style.width = '0%';
                    elements.osValue.textContent = 'Linux only';
                    elements.uptimeValue.textContent = state.status === 'unavailable'
                        ? 'Telemetry unavailable'
                        : 'Refreshes every 4s';
                    drawCpuHistory(elements.cpuChart, []);
                }
                return;
            }

            const cpu = state.cpuPercent;
            elements.cpuValue.textContent = cpu === null ? '...' : `${cpu}%`;
            elements.cpuGauge.style.setProperty('--value', String(cpu || 0));
            elements.cpuGauge.classList.remove('normal', 'warning', 'critical');
            elements.cpuGauge.classList.add(insightsModule.severityForPercent(cpu || 0));
            drawCpuHistory(elements.cpuChart, state.cpuHistory);

            const memoryPercent = percent(state.stats.memory.used_kib, state.stats.memory.total_kib);
            const diskPercent = Number(state.stats.disk.percent) || 0;
            elements.ramValue.textContent = `${insightsModule.formatKib(state.stats.memory.used_kib)} / ${insightsModule.formatKib(state.stats.memory.total_kib)}`;
            elements.diskValue.textContent = `${insightsModule.formatKib(state.stats.disk.used_kib)} / ${insightsModule.formatKib(state.stats.disk.total_kib)}`;
            setResource(elements.ramResource, elements.ramBar, memoryPercent);
            setResource(elements.diskResource, elements.diskBar, diskPercent);
            elements.osValue.textContent = state.stats.os_name;
            elements.uptimeValue.textContent = formatUptime(state.stats.uptime_seconds);
        }

        filesController = filesModule.createController({
            socket,
            render: renderFiles,
            transferClient: root.BinaryTransferClient?.forSocket(socket),
            filePreview: root.FilePreview,
        });
        const insightsController = insightsModule.createController({ socket, render: renderInsights });
        coordinator = workspaceModule.createCoordinator({
            filesPanel: filesController,
            insights: insightsController,
            isDesktop: () => root.matchMedia('(min-width: 851px)').matches,
            render(state) {
                elements.toggle.disabled = !state.sftpEnabled;
                elements.toggle.setAttribute('aria-pressed', String(state.sftpOpen));
                elements.mainSplit.classList.toggle('sftp-open', state.sftpOpen);
                elements.filesPanel.classList.toggle('hidden', !state.sftpOpen);
                root.requestAnimationFrame(() => terminalManager?.fitAllTerminals?.());
            },
        });

        function sync() {
            const activeId = sessionManager.getActiveSession();
            coordinator.update({
                layout: sessionManager.layout,
                sessionId: activeId,
                session: activeId ? sessionManager.getSession(activeId) : null,
            });
        }

        elements.toggle.addEventListener('click', () => coordinator.toggleSftp());
        documentRef.getElementById('sessionFilesCloseBtn')?.addEventListener('click', () => coordinator.toggleSftp());
        documentRef.getElementById('sessionFilesHomeBtn')?.addEventListener('click', () => filesController.goHome());
        documentRef.getElementById('sessionFilesUpBtn')?.addEventListener('click', () => filesController.goParent());
        documentRef.getElementById('sessionFilesRefreshBtn')?.addEventListener('click', () => filesController.refresh());
        documentRef.getElementById('sessionFilesNewFolderBtn')?.addEventListener('click', () => {
            const name = root.prompt('New folder name');
            if (name) filesController.createFolder(name);
        });
        documentRef.getElementById('sessionFilesUploadBtn')?.addEventListener('click', () => elements.uploadInput.click());
        elements.uploadInput.addEventListener('change', () => {
            filesController.upload(elements.uploadInput.files);
            elements.uploadInput.value = '';
        });
        elements.download.addEventListener('click', () => filesController.downloadSelected());
        elements.rename.addEventListener('click', () => {
            const name = root.prompt('Rename selected item');
            if (name) filesController.renameSelected(name);
        });
        elements.delete.addEventListener('click', () => {
            if (root.confirm('Delete the selected remote item?')) filesController.deleteSelected();
        });

        const desktopQuery = root.matchMedia('(min-width: 851px)');
        function syncInsightsVisibility() {
            coordinator.setVisible(
                documentRef.visibilityState !== 'hidden'
                && desktopQuery.matches
                && !elements.notepadPanel?.classList.contains('collapsed')
            );
        }
        root.addEventListener('session-workspace-change', sync);
        documentRef.addEventListener('visibilitychange', syncInsightsVisibility);
        desktopQuery.addEventListener?.('change', () => {
            syncInsightsVisibility();
            sync();
        });
        if (elements.notepadPanel && root.MutationObserver) {
            new MutationObserver(syncInsightsVisibility).observe(elements.notepadPanel, {
                attributes: true,
                attributeFilter: ['class'],
            });
        }
        root.addEventListener('themeChanged', () => drawCpuHistory(elements.cpuChart, []));
        syncInsightsVisibility();
        sync();
        return coordinator;
    }

    root.SessionWorkspaceUI = { init, formatFileSize, formatUptime };
}(window));
