(function (root, factory) {
    const api = factory(root);
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (root && root.document) {
        root.SessionDiagnosticsModule = api;
    }
}(typeof globalThis !== 'undefined' ? globalThis : this, function (root) {
    'use strict';

    const HISTORY_LIMIT = 150;
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
    const SEVERITY_LABELS = {
        normal: 'Normal',
        warning: 'Warning',
        critical: 'Critical',
    };

    function finiteNumber(value) {
        if (value === null || value === undefined || value === '' || typeof value === 'boolean') {
            return null;
        }
        const number = Number(value);
        return Number.isFinite(number) && number >= 0 ? number : null;
    }

    function boundedPercent(value) {
        const number = finiteNumber(value);
        return number === null ? null : Math.max(0, Math.min(100, number));
    }

    function ratioPercent(used, total) {
        const numerator = finiteNumber(used);
        const denominator = finiteNumber(total);
        if (numerator === null || denominator === null || denominator <= 0) return null;
        return (numerator / denominator) * 100;
    }

    function severityForPercent(value) {
        const percent = finiteNumber(value) || 0;
        if (percent >= 90) return 'critical';
        if (percent >= 75) return 'warning';
        return 'normal';
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

    function formatTimestamp(seconds) {
        const sampledAt = finiteNumber(seconds);
        if (sampledAt === null) return null;
        const date = new Date(sampledAt * 1000);
        if (Number.isNaN(date.getTime())) return null;
        return date.toLocaleString([], {
            year: 'numeric', month: 'short', day: '2-digit',
            hour: '2-digit', minute: '2-digit', second: '2-digit',
        });
    }

    function resource(percent, detail, historyKey, history, allowEmpty = false) {
        if (percent === null && !allowEmpty) return null;
        const severity = severityForPercent(percent);
        return {
            percent,
            barPercent: boundedPercent(percent) || 0,
            label: formatPercent(percent) || '--',
            detail,
            severity,
            severityLabel: SEVERITY_LABELS[severity],
            history: history.map(sample => finiteNumber(sample?.[historyKey])),
        };
    }

    function boundedProcesses(rows, percentageKey) {
        if (!Array.isArray(rows)) return [];
        return rows.slice(0, 5).map(row => {
            const percent = finiteNumber(row?.[percentageKey]);
            if (percent === null) return null;
            return {
                pid: String(row.pid),
                user: String(row.user),
                command: String(row.command),
                percent,
                barPercent: boundedPercent(percent),
                label: formatPercent(percent),
            };
        }).filter(Boolean);
    }

    function normalizedHistory(state) {
        const history = Array.isArray(state?.metricHistory) ? state.metricHistory : [];
        return history.slice(-HISTORY_LIMIT).map(sample => ({
            cpuPercent: finiteNumber(sample?.cpuPercent),
            memoryPercent: finiteNumber(sample?.memoryPercent),
            diskPercent: finiteNumber(sample?.diskPercent),
            normalizedLoadPercent: finiteNumber(sample?.normalizedLoadPercent),
            receivedBps: finiteNumber(sample?.receivedBps),
            transmittedBps: finiteNumber(sample?.transmittedBps),
        }));
    }

    function systemdModel(section, filters) {
        if (!section || typeof section !== 'object') return null;
        const services = Array.isArray(section.services) ? section.services : [];
        const status = ['all', 'active', 'failed', 'inactive'].includes(filters.systemdStatus)
            ? filters.systemdStatus
            : 'all';
        const query = String(filters.systemdQuery || '').trim().toLowerCase();
        const rows = services.map(service => ({
            unit: String(service?.unit ?? ''),
            load: String(service?.load ?? ''),
            active: String(service?.active ?? ''),
            sub: String(service?.sub ?? ''),
            description: String(service?.description ?? ''),
        })).filter(service => {
            const active = service.active.toLowerCase();
            const statusMatch = status === 'all'
                || active === status
                || (status === 'inactive' && active !== 'active' && active !== 'failed');
            const searchMatch = !query
                || service.unit.toLowerCase().includes(query)
                || service.description.toLowerCase().includes(query);
            return statusMatch && searchMatch;
        });
        const total = finiteNumber(section.total) || 0;
        const active = finiteNumber(section.active) || 0;
        const failed = finiteNumber(section.failed) || 0;
        const returned = finiteNumber(section.returned) || services.length;
        const inactive = Math.max(0, total - active - failed);
        return {
            state: String(section.state ?? ''),
            total,
            active,
            failed,
            inactive,
            returned,
            truncated: Boolean(section.truncated),
            rows,
            filterStatus: status,
            filterQuery: String(filters.systemdQuery || ''),
            truncationLabel: section.truncated ? `Showing ${returned} of ${total} services` : '',
            distribution: {
                active: total > 0 ? (active / total) * 100 : 0,
                failed: total > 0 ? (failed / total) * 100 : 0,
                inactive: total > 0 ? (inactive / total) * 100 : 0,
            },
        };
    }

    function dockerModel(section, filters) {
        if (!section || typeof section !== 'object') return null;
        const containers = Array.isArray(section.containers) ? section.containers : [];
        const query = String(filters.dockerQuery || '').trim().toLowerCase();
        const rows = containers.map(container => ({
            name: String(container?.name ?? ''),
            status: String(container?.status ?? ''),
        })).filter(container => !query
            || container.name.toLowerCase().includes(query)
            || container.status.toLowerCase().includes(query));
        const total = finiteNumber(section.total) || 0;
        const running = finiteNumber(section.running) || 0;
        const returned = finiteNumber(section.returned) || containers.length;
        const stopped = Math.max(0, total - running);
        return {
            version: String(section.version ?? ''),
            total,
            running,
            stopped,
            returned,
            truncated: Boolean(section.truncated),
            rows,
            filterQuery: String(filters.dockerQuery || ''),
            truncationLabel: section.truncated ? `Showing ${returned} of ${total} containers` : '',
            distribution: {
                running: total > 0 ? (running / total) * 100 : 0,
                stopped: total > 0 ? (stopped / total) * 100 : 0,
            },
        };
    }

    function buildViewModel(state = {}, session = null, inventoryState = {}, filters = {}) {
        const stats = state.stats || null;
        const available = Boolean(state.sessionId && stats);
        const host = session ? `${session.username}@${session.host}` : 'No active session';
        const history = normalizedHistory(state);
        const scopedInventoryState = (
            state.sessionId && inventoryState?.sessionId === state.sessionId
        ) ? inventoryState : {};
        const permissionNotices = [];
        const addPermission = scope => {
            const notice = PERMISSION_NOTICES[scope];
            if (notice && !permissionNotices.includes(notice)) permissionNotices.push(notice);
        };
        (Array.isArray(stats?.permission_denied) ? stats.permission_denied : []).forEach(addPermission);
        const inventoryPermissions = Array.isArray(scopedInventoryState.permissionDenied)
            ? scopedInventoryState.permissionDenied
            : [];
        inventoryPermissions.forEach(addPermission);

        const memoryPercent = ratioPercent(stats?.memory?.used_kib, stats?.memory?.total_kib);
        const diskPercent = finiteNumber(stats?.disk?.percent);
        const loadOne = finiteNumber(stats?.load?.one);
        const cpuCount = finiteNumber(stats?.load?.cpu_count);
        const loadPercent = loadOne !== null && cpuCount > 0 ? (loadOne / cpuCount) * 100 : null;
        const swapPercent = ratioPercent(stats?.swap?.used_kib, stats?.swap?.total_kib);
        const processes = stats?.processes;
        const topCpu = boundedProcesses(processes?.top_cpu, 'cpu_percent');
        const topMemory = boundedProcesses(processes?.top_memory, 'memory_percent');
        const inventory = scopedInventoryState.inventory || null;
        const sampledAt = finiteNumber(scopedInventoryState.sampledAt);

        return {
            available,
            host,
            os: stats?.os_name ? String(stats.os_name) : null,
            status: STATUS_LABELS[state.status] || 'Offline',
            statusClass: state.status || 'disconnected',
            resources: {
                cpu: available ? resource(
                    finiteNumber(state.cpuPercent), 'Current utilization', 'cpuPercent', history, true,
                ) : null,
                memory: available ? resource(
                    memoryPercent,
                    memoryPercent === null ? '' : `${formatKib(stats.memory.used_kib)} of ${formatKib(stats.memory.total_kib)}`,
                    'memoryPercent', history,
                ) : null,
                disk: available ? resource(
                    diskPercent,
                    diskPercent === null ? '' : `${formatKib(stats.disk.used_kib)} of ${formatKib(stats.disk.total_kib)} on /`,
                    'diskPercent', history,
                ) : null,
                load: available ? resource(
                    loadPercent,
                    loadPercent === null ? '' : `Load ${loadOne.toFixed(2)} across ${cpuCount} CPUs`,
                    'normalizedLoadPercent', history,
                ) : null,
            },
            charts: {
                pressureHistory: history.map(sample => ({
                    cpuPercent: sample.cpuPercent,
                    memoryPercent: sample.memoryPercent,
                    normalizedLoadPercent: sample.normalizedLoadPercent,
                })),
                networkHistory: history.map(sample => ({
                    receivedBps: sample.receivedBps,
                    transmittedBps: sample.transmittedBps,
                })),
            },
            secondary: {
                swap: swapPercent === null ? null : {
                    percent: swapPercent,
                    barPercent: boundedPercent(swapPercent),
                    label: formatPercent(swapPercent),
                    detail: `${formatKib(stats.swap.used_kib)} of ${formatKib(stats.swap.total_kib)}`,
                    severity: severityForPercent(swapPercent),
                },
                uptime: formatUptime(stats?.uptime_seconds),
                processTotal: finiteNumber(processes?.total),
                processZombies: finiteNumber(processes?.zombies),
                received: formatRate(state.networkRates?.received_bps),
                transmitted: formatRate(state.networkRates?.transmitted_bps),
            },
            processes: processes && (topCpu.length || topMemory.length)
                ? { total: finiteNumber(processes.total), zombies: finiteNumber(processes.zombies), topCpu, topMemory }
                : null,
            inventory: {
                status: scopedInventoryState.status || 'disconnected',
                stale: scopedInventoryState.status === 'stale',
                loading: scopedInventoryState.status === 'loading',
                sampledAt,
                sampledAtLabel: formatTimestamp(sampledAt),
            },
            systemd: inventoryPermissions.includes('systemd')
                ? null
                : systemdModel(inventory?.systemd, filters),
            docker: inventoryPermissions.includes('docker')
                ? null
                : dockerModel(inventory?.docker, filters),
            permissionNotices,
        };
    }

    function createController(options) {
        const documentRef = options.document;
        const windowRef = options.window || root;
        const onOpenChange = options.onOpenChange || (() => {});
        const onRefreshInventory = options.onRefreshInventory || (() => {});
        const inventoryModule = options.inventoryModule || windowRef?.SessionRuntimeInventoryModule;
        const chartModule = options.chartModule || windowRef?.SessionDiagnosticsCharts;
        const byId = id => documentRef.getElementById(id);
        const elements = {
            trigger: byId('sessionDiagnosticsToggle'), overlay: byId('sessionDiagnosticsOverlay'),
            drawer: documentRef.querySelector?.('.session-diagnostics-drawer'),
            backdrop: byId('sessionDiagnosticsBackdrop'), close: byId('sessionDiagnosticsClose'),
            refresh: byId('sessionDiagnosticsRefresh'), lastUpdated: byId('sessionDiagnosticsLastUpdated'),
            host: byId('sessionDiagnosticsHost'), os: byId('sessionDiagnosticsOs'), state: byId('sessionDiagnosticsState'),
            permissions: byId('sessionDiagnosticsPermissions'), permissionList: byId('sessionDiagnosticsPermissionList'),
            pressureSection: byId('sessionDiagnosticsPressureSection'), pressureChart: byId('sessionDiagnosticsPressureChart'),
            networkSection: byId('sessionDiagnosticsNetworkSection'), networkChart: byId('sessionDiagnosticsNetworkChart'),
            networkReceived: byId('sessionDiagnosticsNetworkReceived'), networkTransmitted: byId('sessionDiagnosticsNetworkTransmitted'),
            swapMetric: byId('sessionDiagnosticsSwapMetric'), swapValue: byId('sessionDiagnosticsSwapValue'),
            swapDetail: byId('sessionDiagnosticsSwapDetail'), swapBar: byId('sessionDiagnosticsSwapBar'),
            uptimeMetric: byId('sessionDiagnosticsUptimeMetric'), uptimeValue: byId('sessionDiagnosticsUptimeValue'),
            processMetric: byId('sessionDiagnosticsProcessMetric'), processValue: byId('sessionDiagnosticsProcessValue'),
            processDetail: byId('sessionDiagnosticsProcessDetail'), processesSection: byId('sessionDiagnosticsProcessesSection'),
            cpuProcessesPanel: byId('sessionDiagnosticsCpuProcessesPanel'), memoryProcessesPanel: byId('sessionDiagnosticsMemoryProcessesPanel'),
            cpuProcesses: byId('sessionDiagnosticsCpuProcesses'), memoryProcesses: byId('sessionDiagnosticsMemoryProcesses'),
            systemdSection: byId('sessionDiagnosticsSystemdSection'), systemdState: byId('sessionDiagnosticsSystemdState'),
            systemdCounts: byId('sessionDiagnosticsSystemdCounts'), systemdTruncation: byId('sessionDiagnosticsSystemdTruncation'),
            systemdDistribution: byId('sessionDiagnosticsSystemdDistribution'), systemdSearch: byId('sessionDiagnosticsSystemdSearch'),
            systemdServices: byId('sessionDiagnosticsSystemdServices'),
            dockerSection: byId('sessionDiagnosticsDockerSection'), dockerVersion: byId('sessionDiagnosticsDockerVersion'),
            dockerCounts: byId('sessionDiagnosticsDockerCounts'), dockerTruncation: byId('sessionDiagnosticsDockerTruncation'),
            dockerDistribution: byId('sessionDiagnosticsDockerDistribution'), dockerSearch: byId('sessionDiagnosticsDockerSearch'),
            dockerContainers: byId('sessionDiagnosticsDockerContainers'), clipboardFeedback: byId('sessionDiagnosticsClipboardFeedback'),
        };
        ['cpu', 'memory', 'disk', 'load'].forEach(key => {
            const title = key.charAt(0).toUpperCase() + key.slice(1);
            elements[`${key}Metric`] = byId(`sessionDiagnostics${title}Metric`);
            elements[`${key}Value`] = byId(`sessionDiagnostics${title}Value`);
            elements[`${key}Detail`] = byId(`sessionDiagnostics${title}Detail`);
            elements[`${key}Severity`] = byId(`sessionDiagnostics${title}Severity`);
            elements[`${key}Bar`] = byId(`sessionDiagnostics${title}Bar`);
            elements[`${key}Sparkline`] = byId(`sessionDiagnostics${title}Sparkline`);
        });
        if (!elements.trigger || !elements.overlay || !elements.close) return null;

        let open = false;
        let activeSessionId = null;
        let previousFocus = null;
        let latestState = {};
        let latestSession = null;
        let latestInventoryState = {};
        let latestModel = null;
        let redrawFrame = null;
        const filters = { systemdStatus: 'all', systemdQuery: '', dockerQuery: '' };
        const filterButtons = Array.from(elements.overlay.querySelectorAll?.('[data-systemd-filter]') || []);

        function defaultWriteClipboard(text) {
            if (windowRef?.navigator?.clipboard?.writeText) {
                return windowRef.navigator.clipboard.writeText(text);
            }
            return new Promise((resolve, reject) => {
                const input = documentRef.createElement('textarea');
                input.value = text;
                input.setAttribute('readonly', '');
                input.style.position = 'fixed';
                input.style.opacity = '0';
                documentRef.body?.appendChild(input);
                input.select?.();
                try {
                    if (!documentRef.execCommand?.('copy')) throw new Error('copy unavailable');
                    resolve();
                } catch (error) {
                    reject(error);
                } finally {
                    input.remove?.();
                }
            });
        }
        const writeClipboard = options.writeClipboard || defaultWriteClipboard;

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
                scheduleRedraw();
            } else if (restoreFocus) {
                const focusTarget = previousFocus && documentRef.contains(previousFocus) ? previousFocus : elements.trigger;
                focusTarget?.focus?.();
            }
            onOpenChange(open);
        }

        function replaceList(container, values) {
            container.replaceChildren();
            values.forEach(value => {
                const item = documentRef.createElement('li');
                item.textContent = value;
                container.appendChild(item);
            });
        }

        function setResource(key, value) {
            const wrapper = elements[`${key}Metric`];
            wrapper.hidden = !value;
            if (!value) return;
            wrapper.classList.remove('normal', 'warning', 'critical');
            wrapper.classList.add(value.severity);
            elements[`${key}Value`].textContent = value.label;
            elements[`${key}Detail`].textContent = value.detail || '';
            elements[`${key}Severity`].textContent = value.severityLabel;
            elements[`${key}Bar`].style.width = `${value.barPercent}%`;
        }

        function replaceProcesses(container, rows) {
            container.replaceChildren();
            rows.forEach(row => {
                const tr = documentRef.createElement('tr');
                [row.command, row.user, row.pid].forEach(value => {
                    const cell = documentRef.createElement('td');
                    cell.textContent = value;
                    tr.appendChild(cell);
                });
                const percentCell = documentRef.createElement('td');
                const percent = documentRef.createElement('div');
                const bar = documentRef.createElement('div');
                const fill = documentRef.createElement('span');
                const label = documentRef.createElement('span');
                percentCell.className = 'session-percent-cell';
                percent.className = 'session-process-percent';
                bar.className = 'session-diagnostics-bar';
                fill.style.width = `${row.barPercent}%`;
                label.textContent = row.label;
                bar.appendChild(fill);
                percent.append(bar, label);
                percentCell.appendChild(percent);
                tr.appendChild(percentCell);
                container.appendChild(tr);
            });
        }

        function emptyTableRow(container, columns, message) {
            const tr = documentRef.createElement('tr');
            const td = documentRef.createElement('td');
            td.colSpan = columns;
            td.textContent = message;
            tr.appendChild(td);
            container.appendChild(tr);
        }

        function copyActionButton(action, service) {
            const button = documentRef.createElement('button');
            const serviceContext = documentRef.createElement('span');
            button.type = 'button';
            button.dataset.action = action;
            button.textContent = action.charAt(0).toUpperCase() + action.slice(1);
            serviceContext.className = 'sr-only';
            serviceContext.textContent = ` for ${service.unit}`;
            button.appendChild(serviceContext);
            button.addEventListener('click', async () => {
                try {
                    const command = await inventoryModule?.copySystemdCommand(action, service.unit, writeClipboard);
                    elements.clipboardFeedback.textContent = command
                        ? `Command copied: ${action} ${service.unit}`
                        : 'Copy failed';
                    if (command) {
                        windowRef?.showNotification?.('Command copied to clipboard', 'success');
                    } else {
                        windowRef?.showNotification?.('Failed to copy command', 'error');
                    }
                } catch {
                    elements.clipboardFeedback.textContent = 'Copy failed';
                    windowRef?.showNotification?.('Failed to copy command', 'error');
                }
            });
            return button;
        }

        function renderSystemd(model) {
            elements.systemdSection.hidden = !model;
            if (!model) return;
            elements.systemdState.textContent = model.state;
            elements.systemdCounts.textContent = `${model.rows.length} shown - ${model.active} active - ${model.failed} failed - ${model.inactive} inactive`;
            elements.systemdTruncation.textContent = model.truncationLabel;
            if (elements.systemdSearch.value !== model.filterQuery) {
                elements.systemdSearch.value = model.filterQuery;
            }
            filterButtons.forEach(button => {
                button.setAttribute('aria-pressed', String(button.dataset.systemdFilter === model.filterStatus));
            });
            const distribution = elements.systemdDistribution.children;
            if (distribution[0]) distribution[0].style.width = `${model.distribution.active}%`;
            if (distribution[1]) distribution[1].style.width = `${model.distribution.failed}%`;
            if (distribution[2]) distribution[2].style.width = `${model.distribution.inactive}%`;
            elements.systemdServices.replaceChildren();
            model.rows.forEach(service => {
                const tr = documentRef.createElement('tr');
                const unit = documentRef.createElement('th');
                const load = documentRef.createElement('td');
                const state = documentRef.createElement('td');
                const description = documentRef.createElement('td');
                const actions = documentRef.createElement('td');
                const stateChip = documentRef.createElement('span');
                const buttons = documentRef.createElement('div');
                unit.scope = 'row';
                unit.textContent = service.unit;
                load.textContent = service.load;
                stateChip.className = `session-state-chip ${service.active === 'active' || service.active === 'failed' ? service.active : 'inactive'}`;
                stateChip.textContent = `${service.active} / ${service.sub}`;
                state.appendChild(stateChip);
                description.textContent = service.description;
                buttons.className = 'session-service-actions';
                ['start', 'stop', 'restart'].forEach(action => buttons.appendChild(copyActionButton(action, service)));
                actions.appendChild(buttons);
                tr.append(unit, load, state, description, actions);
                elements.systemdServices.appendChild(tr);
            });
            if (!model.rows.length) emptyTableRow(elements.systemdServices, 5, 'No matching services');
        }

        function renderDocker(model) {
            elements.dockerSection.hidden = !model;
            if (!model) return;
            elements.dockerVersion.textContent = model.version ? `Docker ${model.version}` : 'Docker';
            elements.dockerCounts.textContent = `${model.rows.length} shown - ${model.running} running - ${model.total} total`;
            elements.dockerTruncation.textContent = model.truncationLabel;
            if (elements.dockerSearch.value !== model.filterQuery) {
                elements.dockerSearch.value = model.filterQuery;
            }
            const distribution = elements.dockerDistribution.children;
            if (distribution[0]) distribution[0].style.width = `${model.distribution.running}%`;
            if (distribution[1]) distribution[1].style.width = `${model.distribution.stopped}%`;
            elements.dockerContainers.replaceChildren();
            model.rows.forEach(container => {
                const tr = documentRef.createElement('tr');
                const name = documentRef.createElement('td');
                const status = documentRef.createElement('td');
                name.textContent = container.name;
                status.textContent = container.status;
                tr.append(name, status);
                elements.dockerContainers.appendChild(tr);
            });
            if (!model.rows.length) emptyTableRow(elements.dockerContainers, 2, 'No matching containers');
        }

        function drawCharts() {
            if (!latestModel || !chartModule) return;
            const model = latestModel;
            ['cpu', 'memory', 'disk', 'load'].forEach(key => {
                if (!model.resources[key]) return;
                chartModule.drawSparkline(elements[`${key}Sparkline`], model.resources[key].history, {
                    key: 'sparkline', label: `${key} utilization`, max: 100,
                });
            });
            if (!elements.pressureSection.hidden) {
                chartModule.drawLineChart(
                    elements.pressureChart,
                    chartModule.buildPressureSeries(model.charts.pressureHistory),
                );
            }
            if (!elements.networkSection.hidden) {
                chartModule.drawLineChart(
                    elements.networkChart,
                    chartModule.buildNetworkSeries(model.charts.networkHistory),
                    { formatValue: value => formatRate(value) || '0 B/s' },
                );
            }
        }

        function scheduleRedraw() {
            if (!open || redrawFrame !== null) return;
            const requestFrame = windowRef?.requestAnimationFrame || (callback => setTimeout(callback, 0));
            redrawFrame = requestFrame(() => {
                redrawFrame = null;
                drawCharts();
            });
        }

        function render(state, session, inventoryState) {
            latestState = state || {};
            latestSession = session || null;
            latestInventoryState = inventoryState || {};
            const nextSessionId = state?.sessionId || null;
            if (activeSessionId && activeSessionId !== nextSessionId && open) setOpen(false, false);
            activeSessionId = nextSessionId;
            latestModel = buildViewModel(latestState, latestSession, latestInventoryState, filters);
            const model = latestModel;
            elements.trigger.disabled = !model.available;
            if (!model.available && open) setOpen(false, false);
            elements.host.textContent = model.host;
            elements.os.textContent = model.os || '';
            elements.os.hidden = !model.os;
            elements.state.textContent = model.status;
            elements.state.className = `session-insights-state ${model.statusClass}`;
            elements.refresh.disabled = !model.available || model.inventory.loading;
            elements.refresh.setAttribute('aria-busy', String(model.inventory.loading));
            elements.lastUpdated.textContent = model.inventory.sampledAtLabel
                ? `${model.inventory.stale ? 'Inventory stale - ' : ''}Last updated ${model.inventory.sampledAtLabel}`
                : (model.inventory.loading ? 'Loading inventory' : 'Inventory not loaded');

            ['cpu', 'memory', 'disk', 'load'].forEach(key => setResource(key, model.resources[key]));
            elements.pressureSection.hidden = !model.available;
            const hasNetwork = Boolean(
                model.secondary.received || model.secondary.transmitted
                || model.charts.networkHistory.some(sample => sample.receivedBps !== null || sample.transmittedBps !== null)
            );
            elements.networkSection.hidden = !hasNetwork;
            elements.networkReceived.textContent = model.secondary.received || '--';
            elements.networkTransmitted.textContent = model.secondary.transmitted || '--';

            const swap = model.secondary.swap;
            elements.swapMetric.hidden = !swap;
            if (swap) {
                elements.swapMetric.classList.remove('normal', 'warning', 'critical');
                elements.swapMetric.classList.add(swap.severity);
                elements.swapValue.textContent = swap.label;
                elements.swapDetail.textContent = swap.detail;
                elements.swapBar.style.width = `${swap.barPercent}%`;
            }
            elements.uptimeMetric.hidden = !model.secondary.uptime;
            elements.uptimeValue.textContent = model.secondary.uptime || '';
            elements.processMetric.hidden = model.secondary.processTotal === null;
            elements.processValue.textContent = model.secondary.processTotal === null ? '' : String(model.secondary.processTotal);
            elements.processDetail.textContent = model.secondary.processZombies === null
                ? ''
                : `${model.secondary.processZombies} zombie${model.secondary.processZombies === 1 ? '' : 's'}`;

            elements.permissions.hidden = model.permissionNotices.length === 0;
            replaceList(elements.permissionList, model.permissionNotices);
            elements.processesSection.hidden = !model.processes;
            if (model.processes) {
                elements.cpuProcessesPanel.hidden = model.processes.topCpu.length === 0;
                elements.memoryProcessesPanel.hidden = model.processes.topMemory.length === 0;
                replaceProcesses(elements.cpuProcesses, model.processes.topCpu);
                replaceProcesses(elements.memoryProcesses, model.processes.topMemory);
            }
            renderSystemd(model.systemd);
            renderDocker(model.docker);
            scheduleRedraw();
        }

        function rerenderLocal() {
            render(latestState, latestSession, latestInventoryState);
        }

        function handleKeydown(event) {
            if (!open) return;
            if (event.key === 'Escape') {
                event.preventDefault();
                setOpen(false);
                return;
            }
            if (event.key !== 'Tab') return;
            const focusable = Array.from(elements.drawer?.querySelectorAll?.(
                'button:not([disabled]), input:not([disabled]), [href], [tabindex]:not([tabindex="-1"])',
            ) || []).filter(element => !element.hidden && !element.closest?.('[hidden]'));
            if (!focusable.length) return;
            const first = focusable[0];
            const last = focusable[focusable.length - 1];
            if (event.shiftKey && documentRef.activeElement === first) {
                event.preventDefault();
                last.focus();
            } else if (!event.shiftKey && documentRef.activeElement === last) {
                event.preventDefault();
                first.focus();
            }
        }

        const handleTrigger = () => setOpen(!open);
        const handleClose = () => setOpen(false);
        const handleRefresh = () => onRefreshInventory();
        const handleSystemdSearch = event => { filters.systemdQuery = event.target.value; rerenderLocal(); };
        const handleDockerSearch = event => { filters.dockerQuery = event.target.value; rerenderLocal(); };
        const filterHandlers = new Map();
        filterButtons.forEach(button => {
            const handler = () => { filters.systemdStatus = button.dataset.systemdFilter; rerenderLocal(); };
            filterHandlers.set(button, handler);
            button.addEventListener('click', handler);
        });
        elements.trigger.addEventListener('click', handleTrigger);
        elements.close.addEventListener('click', handleClose);
        elements.refresh?.addEventListener('click', handleRefresh);
        elements.backdrop?.addEventListener('click', handleClose);
        elements.systemdSearch?.addEventListener('input', handleSystemdSearch);
        elements.dockerSearch?.addEventListener('input', handleDockerSearch);
        documentRef.addEventListener('keydown', handleKeydown);
        windowRef?.addEventListener?.('themeChanged', scheduleRedraw);
        const ResizeObserverCtor = options.ResizeObserver || windowRef?.ResizeObserver;
        const resizeObserver = ResizeObserverCtor ? new ResizeObserverCtor(scheduleRedraw) : null;
        if (resizeObserver && elements.drawer) resizeObserver.observe(elements.drawer);
        elements.trigger.disabled = true;

        return {
            render,
            redraw: scheduleRedraw,
            isOpen: () => open,
            close: () => setOpen(false),
            destroy() {
                setOpen(false, false);
                elements.trigger.removeEventListener('click', handleTrigger);
                elements.close.removeEventListener('click', handleClose);
                elements.refresh?.removeEventListener('click', handleRefresh);
                elements.backdrop?.removeEventListener('click', handleClose);
                elements.systemdSearch?.removeEventListener('input', handleSystemdSearch);
                elements.dockerSearch?.removeEventListener('input', handleDockerSearch);
                filterHandlers.forEach((handler, button) => button.removeEventListener('click', handler));
                documentRef.removeEventListener('keydown', handleKeydown);
                windowRef?.removeEventListener?.('themeChanged', scheduleRedraw);
                resizeObserver?.disconnect?.();
                if (redrawFrame !== null) {
                    windowRef?.cancelAnimationFrame?.(redrawFrame);
                    redrawFrame = null;
                }
            },
        };
    }

    return { buildViewModel, createController, formatRate };
}));
