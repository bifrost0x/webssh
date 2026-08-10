(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (root && root.document) {
        root.SessionDiagnosticsModule = api;
    }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    'use strict';

    const STATUS_LABELS = {
        ready: 'Live',
        loading: 'Sampling',
        stale: 'Stale',
        unavailable: 'Unavailable',
        disconnected: 'Offline',
    };
    const PERMISSION_NOTICES = {
        docker: 'Docker is installed, but this SSH user cannot access the Docker daemon.',
        processes: 'Process details are restricted for this SSH user.',
        systemd: 'systemd service details are restricted for this SSH user.',
    };

    function finiteNumber(value) {
        const number = Number(value);
        return Number.isFinite(number) && number >= 0 ? number : null;
    }

    function formatKib(value) {
        const kib = finiteNumber(value);
        if (kib === null) return null;
        const mib = kib / 1024;
        if (mib < 1024) return `${mib.toFixed(1)} MB`;
        return `${(mib / 1024).toFixed(1)} GB`;
    }

    function formatRate(value) {
        const bytes = finiteNumber(value);
        if (bytes === null) return null;
        if (bytes < 1024) return `${Math.round(bytes)} B/s`;
        const kib = bytes / 1024;
        if (kib < 1024) return `${kib.toFixed(1)} KB/s`;
        const mib = kib / 1024;
        if (mib < 1024) return `${mib.toFixed(1)} MB/s`;
        return `${(mib / 1024).toFixed(1)} GB/s`;
    }

    function formatUptime(seconds) {
        const total = finiteNumber(seconds);
        if (total === null) return null;
        const days = Math.floor(total / 86400);
        const hours = Math.floor((total % 86400) / 3600);
        const minutes = Math.floor((total % 3600) / 60);
        if (days > 0) return `${days}d ${hours}h`;
        return `${hours}h ${minutes}m`;
    }

    function formatPercent(value) {
        const number = finiteNumber(value);
        return number === null ? null : `${number.toFixed(1)}%`;
    }

    function boundedProcesses(rows) {
        if (!Array.isArray(rows)) return [];
        return rows.slice(0, 5).map(row => ({
            pid: String(row.pid),
            user: String(row.user),
            command: String(row.command),
            cpu: formatPercent(row.cpu_percent),
            memory: formatPercent(row.memory_percent),
        })).filter(row => row.cpu !== null && row.memory !== null);
    }

    function buildViewModel(state = {}, session = null) {
        const stats = state.stats || null;
        const available = Boolean(state.sessionId && stats);
        const host = session
            ? `${session.username}@${session.host}`
            : 'No active session';
        const model = {
            available,
            host,
            status: STATUS_LABELS[state.status] || 'Offline',
            statusClass: state.status || 'disconnected',
            os: stats?.os_name || null,
            summary: {
                cpu: finiteNumber(state.cpuPercent) === null
                    ? null
                    : `${Math.round(Number(state.cpuPercent))}%`,
                memoryUsed: formatKib(stats?.memory?.used_kib),
                memoryTotal: formatKib(stats?.memory?.total_kib),
                diskUsed: formatKib(stats?.disk?.used_kib),
                diskTotal: formatKib(stats?.disk?.total_kib),
                uptime: formatUptime(stats?.uptime_seconds),
            },
            sections: {
                load: null,
                swap: null,
                network: null,
                processes: null,
                systemd: null,
                docker: null,
            },
            permissionNotices: [],
        };
        if (!available) return model;

        const load = stats.load;
        if (
            finiteNumber(load?.one) !== null
            && finiteNumber(load?.five) !== null
            && finiteNumber(load?.fifteen) !== null
            && finiteNumber(load?.cpu_count) > 0
        ) {
            model.sections.load = {
                one: Number(load.one).toFixed(2),
                five: Number(load.five).toFixed(2),
                fifteen: Number(load.fifteen).toFixed(2),
                cpuCount: Number(load.cpu_count),
            };
        }

        const swap = stats.swap;
        if (finiteNumber(swap?.total_kib) > 0) {
            model.sections.swap = {
                used: formatKib(swap.used_kib),
                total: formatKib(swap.total_kib),
            };
        }

        const rates = state.networkRates;
        const received = formatRate(rates?.received_bps);
        const transmitted = formatRate(rates?.transmitted_bps);
        if (stats.network && received !== null && transmitted !== null) {
            model.sections.network = { received, transmitted };
        }

        const processes = stats.processes;
        const topCpu = boundedProcesses(processes?.top_cpu);
        const topMemory = boundedProcesses(processes?.top_memory);
        if (processes && (topCpu.length || topMemory.length)) {
            model.sections.processes = {
                total: Number(processes.total),
                zombies: Number(processes.zombies),
                topCpu,
                topMemory,
            };
        }

        if (stats.systemd) {
            model.sections.systemd = {
                state: String(stats.systemd.state),
                running: Number(stats.systemd.running),
                failed: Number(stats.systemd.failed),
                failedUnits: Array.isArray(stats.systemd.failed_units)
                    ? stats.systemd.failed_units.slice(0, 5).map(String)
                    : [],
            };
        }

        if (stats.docker) {
            model.sections.docker = {
                version: String(stats.docker.version),
                running: Number(stats.docker.running),
                total: Number(stats.docker.total),
                containers: Array.isArray(stats.docker.containers)
                    ? stats.docker.containers.slice(0, 5).map(container => ({
                        name: String(container.name),
                        status: String(container.status),
                    }))
                    : [],
            };
        }

        const seenPermissions = new Set();
        (Array.isArray(stats.permission_denied) ? stats.permission_denied : [])
            .forEach(scope => {
                if (PERMISSION_NOTICES[scope] && !seenPermissions.has(scope)) {
                    seenPermissions.add(scope);
                    model.permissionNotices.push(PERMISSION_NOTICES[scope]);
                }
            });
        return model;
    }

    function createController(options) {
        const documentRef = options.document;
        const onOpenChange = options.onOpenChange || (() => {});
        const byId = id => documentRef.getElementById(id);
        const elements = {
            trigger: byId('sessionDiagnosticsToggle'),
            overlay: byId('sessionDiagnosticsOverlay'),
            backdrop: byId('sessionDiagnosticsBackdrop'),
            close: byId('sessionDiagnosticsClose'),
            host: byId('sessionDiagnosticsHost'),
            os: byId('sessionDiagnosticsOs'),
            state: byId('sessionDiagnosticsState'),
            permissions: byId('sessionDiagnosticsPermissions'),
            permissionList: byId('sessionDiagnosticsPermissionList'),
            cpuMetric: byId('sessionDiagnosticsCpuMetric'),
            cpuValue: byId('sessionDiagnosticsCpuValue'),
            memoryMetric: byId('sessionDiagnosticsMemoryMetric'),
            memoryValue: byId('sessionDiagnosticsMemoryValue'),
            memoryDetail: byId('sessionDiagnosticsMemoryDetail'),
            diskMetric: byId('sessionDiagnosticsDiskMetric'),
            diskValue: byId('sessionDiagnosticsDiskValue'),
            diskDetail: byId('sessionDiagnosticsDiskDetail'),
            uptimeMetric: byId('sessionDiagnosticsUptimeMetric'),
            uptimeValue: byId('sessionDiagnosticsUptimeValue'),
            loadMetric: byId('sessionDiagnosticsLoadMetric'),
            loadValue: byId('sessionDiagnosticsLoadValue'),
            loadDetail: byId('sessionDiagnosticsLoadDetail'),
            swapMetric: byId('sessionDiagnosticsSwapMetric'),
            swapValue: byId('sessionDiagnosticsSwapValue'),
            swapDetail: byId('sessionDiagnosticsSwapDetail'),
            networkMetric: byId('sessionDiagnosticsNetworkMetric'),
            networkValue: byId('sessionDiagnosticsNetworkValue'),
            networkDetail: byId('sessionDiagnosticsNetworkDetail'),
            processMetric: byId('sessionDiagnosticsProcessMetric'),
            processValue: byId('sessionDiagnosticsProcessValue'),
            processDetail: byId('sessionDiagnosticsProcessDetail'),
            processesSection: byId('sessionDiagnosticsProcessesSection'),
            cpuProcessesPanel: byId('sessionDiagnosticsCpuProcessesPanel'),
            memoryProcessesPanel: byId('sessionDiagnosticsMemoryProcessesPanel'),
            cpuProcesses: byId('sessionDiagnosticsCpuProcesses'),
            memoryProcesses: byId('sessionDiagnosticsMemoryProcesses'),
            systemdSection: byId('sessionDiagnosticsSystemdSection'),
            systemdState: byId('sessionDiagnosticsSystemdState'),
            systemdCounts: byId('sessionDiagnosticsSystemdCounts'),
            systemdFailures: byId('sessionDiagnosticsSystemdFailures'),
            dockerSection: byId('sessionDiagnosticsDockerSection'),
            dockerVersion: byId('sessionDiagnosticsDockerVersion'),
            dockerCounts: byId('sessionDiagnosticsDockerCounts'),
            dockerContainers: byId('sessionDiagnosticsDockerContainers'),
        };
        if (!elements.trigger || !elements.overlay || !elements.close) return null;

        let open = false;
        let activeSessionId = null;
        let previousFocus = null;

        function setOpen(nextOpen, restoreFocus = true) {
            const normalized = Boolean(nextOpen && !elements.trigger.disabled);
            if (open === normalized) return;
            open = normalized;
            elements.overlay.classList.toggle('hidden', !open);
            elements.overlay.setAttribute('aria-hidden', String(!open));
            elements.trigger.setAttribute('aria-expanded', String(open));
            documentRef.body?.classList.toggle('session-diagnostics-open', open);
            if (open) {
                previousFocus = documentRef.activeElement;
                elements.close.focus();
            } else if (restoreFocus) {
                const focusTarget = previousFocus && documentRef.contains(previousFocus)
                    ? previousFocus
                    : elements.trigger;
                focusTarget?.focus?.();
            }
            onOpenChange(open);
        }

        function setMetric(wrapper, valueElement, value, detailElement, detail) {
            const visible = value !== null && value !== undefined;
            wrapper.hidden = !visible;
            if (!visible) return;
            valueElement.textContent = value;
            if (detailElement) detailElement.textContent = detail || '';
        }

        function replaceList(container, values, formatter) {
            container.replaceChildren();
            values.forEach(value => {
                const item = documentRef.createElement('li');
                formatter(item, value);
                container.appendChild(item);
            });
        }

        function replaceProcesses(container, rows, key) {
            container.replaceChildren();
            rows.forEach(row => {
                const tr = documentRef.createElement('tr');
                [row.command, row.user, row.pid, row[key]].forEach(value => {
                    const cell = documentRef.createElement('td');
                    cell.textContent = value;
                    tr.appendChild(cell);
                });
                container.appendChild(tr);
            });
        }

        function render(state, session) {
            const nextSessionId = state?.sessionId || null;
            if (activeSessionId && activeSessionId !== nextSessionId && open) {
                setOpen(false, false);
            }
            activeSessionId = nextSessionId;
            const model = buildViewModel(state, session);
            elements.trigger.disabled = !model.available;
            if (!model.available && open) setOpen(false, false);
            elements.host.textContent = model.host;
            elements.os.textContent = model.os || '';
            elements.os.hidden = !model.os;
            elements.state.textContent = model.status;
            elements.state.className = `session-insights-state ${model.statusClass}`;

            setMetric(elements.cpuMetric, elements.cpuValue, model.summary.cpu);
            setMetric(
                elements.memoryMetric,
                elements.memoryValue,
                model.summary.memoryUsed,
                elements.memoryDetail,
                model.summary.memoryTotal ? `of ${model.summary.memoryTotal}` : '',
            );
            setMetric(
                elements.diskMetric,
                elements.diskValue,
                model.summary.diskUsed,
                elements.diskDetail,
                model.summary.diskTotal ? `of ${model.summary.diskTotal} on /` : '',
            );
            setMetric(
                elements.uptimeMetric,
                elements.uptimeValue,
                model.summary.uptime,
            );

            const load = model.sections.load;
            setMetric(
                elements.loadMetric,
                elements.loadValue,
                load?.one,
                elements.loadDetail,
                load ? `${load.five} / ${load.fifteen} - ${load.cpuCount} CPUs` : '',
            );
            const swap = model.sections.swap;
            setMetric(
                elements.swapMetric,
                elements.swapValue,
                swap?.used,
                elements.swapDetail,
                swap ? `of ${swap.total}` : '',
            );
            const network = model.sections.network;
            setMetric(
                elements.networkMetric,
                elements.networkValue,
                network?.received,
                elements.networkDetail,
                network ? `${network.transmitted} sent` : '',
            );
            const processes = model.sections.processes;
            setMetric(
                elements.processMetric,
                elements.processValue,
                processes ? String(processes.total) : null,
                elements.processDetail,
                processes ? `${processes.zombies} zombie` : '',
            );

            elements.permissions.hidden = model.permissionNotices.length === 0;
            replaceList(elements.permissionList, model.permissionNotices, (item, notice) => {
                item.textContent = notice;
            });

            elements.processesSection.hidden = !processes;
            if (processes) {
                elements.cpuProcessesPanel.hidden = processes.topCpu.length === 0;
                elements.memoryProcessesPanel.hidden = processes.topMemory.length === 0;
                replaceProcesses(elements.cpuProcesses, processes.topCpu, 'cpu');
                replaceProcesses(elements.memoryProcesses, processes.topMemory, 'memory');
            }

            const systemd = model.sections.systemd;
            elements.systemdSection.hidden = !systemd;
            if (systemd) {
                elements.systemdState.textContent = systemd.state;
                elements.systemdCounts.textContent = `${systemd.running} active - ${systemd.failed} failed`;
                elements.systemdFailures.hidden = systemd.failedUnits.length === 0;
                replaceList(elements.systemdFailures, systemd.failedUnits, (item, unit) => {
                    item.textContent = unit;
                });
            }

            const docker = model.sections.docker;
            elements.dockerSection.hidden = !docker;
            if (docker) {
                elements.dockerVersion.textContent = `Docker ${docker.version}`;
                elements.dockerCounts.textContent = `${docker.running} running - ${docker.total} total`;
                elements.dockerContainers.hidden = docker.containers.length === 0;
                replaceList(elements.dockerContainers, docker.containers, (item, container) => {
                    const name = documentRef.createElement('strong');
                    const status = documentRef.createElement('span');
                    name.textContent = container.name;
                    status.textContent = container.status;
                    item.append(name, status);
                });
            }
        }

        function handleKeydown(event) {
            if (!open) return;
            if (event.key === 'Escape') {
                event.preventDefault();
                setOpen(false);
                return;
            }
            if (event.key === 'Tab') {
                event.preventDefault();
                elements.close.focus();
            }
        }

        function handleTrigger() {
            setOpen(!open);
        }

        function handleClose() {
            setOpen(false);
        }

        elements.trigger.addEventListener('click', handleTrigger);
        elements.close.addEventListener('click', handleClose);
        elements.backdrop?.addEventListener('click', handleClose);
        documentRef.addEventListener('keydown', handleKeydown);
        elements.trigger.disabled = true;

        return {
            render,
            isOpen: () => open,
            close: () => setOpen(false),
            destroy() {
                setOpen(false, false);
                elements.trigger.removeEventListener('click', handleTrigger);
                elements.close.removeEventListener('click', handleClose);
                elements.backdrop?.removeEventListener('click', handleClose);
                documentRef.removeEventListener('keydown', handleKeydown);
            },
        };
    }

    return {
        buildViewModel,
        createController,
        formatRate,
    };
}));
