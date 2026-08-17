(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (root && root.document) {
        root.SessionInsightsModule = api;
    }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    'use strict';

    const POLL_INTERVAL_MS = 4000;
    const RESPONSE_TIMEOUT_MS = 3500;
    const BACKOFF_RETRY_MS = 60000;
    const HISTORY_LIMIT = 150;

    function calculateCpuPercent(previous, current) {
        if (!Array.isArray(previous) || !Array.isArray(current)) return null;
        if (previous.length < 4 || current.length < 4) return null;
        const length = Math.min(previous.length, current.length);
        let totalDelta = 0;
        for (let index = 0; index < length; index += 1) {
            const delta = Number(current[index]) - Number(previous[index]);
            if (!Number.isFinite(delta) || delta < 0) return null;
            totalDelta += delta;
        }
        if (totalDelta <= 0) return null;
        const idleDelta = (
            Number(current[3]) - Number(previous[3])
            + (length > 4 ? Number(current[4]) - Number(previous[4]) : 0)
        );
        if (!Number.isFinite(idleDelta) || idleDelta < 0) return null;
        const percent = Math.round(((totalDelta - idleDelta) / totalDelta) * 100);
        return Math.max(0, Math.min(100, percent));
    }

    function formatKib(value) {
        const kib = Number(value);
        if (!Number.isFinite(kib) || kib < 0) return '—';
        const mib = kib / 1024;
        if (mib < 1024) return `${mib.toFixed(1)} MB`;
        return `${(mib / 1024).toFixed(1)} GB`;
    }

    function severityForPercent(value) {
        const percent = Number(value);
        if (percent >= 90) return 'critical';
        if (percent >= 75) return 'warning';
        return 'normal';
    }

    function calculateNetworkRates(previous, current) {
        if (!previous || !current) return null;
        const elapsedSeconds = (
            Number(current.sampled_at) - Number(previous.sampled_at)
        ) / 1000;
        const receivedDelta = (
            Number(current.received_bytes) - Number(previous.received_bytes)
        );
        const transmittedDelta = (
            Number(current.transmitted_bytes) - Number(previous.transmitted_bytes)
        );
        if (
            !Number.isFinite(elapsedSeconds)
            || !Number.isFinite(receivedDelta)
            || !Number.isFinite(transmittedDelta)
            || elapsedSeconds <= 0
            || receivedDelta < 0
            || transmittedDelta < 0
        ) {
            return null;
        }
        return {
            received_bps: Math.round(receivedDelta / elapsedSeconds),
            transmitted_bps: Math.round(transmittedDelta / elapsedSeconds),
        };
    }

    function percent(used, total) {
        const numerator = nonNegativeNumber(used);
        const denominator = nonNegativeNumber(total);
        if (numerator === null || denominator === null || denominator <= 0) return null;
        return Math.min(100, Math.round((numerator / denominator) * 100));
    }

    function nonNegativeNumber(value) {
        if (value === null || value === undefined || value === '' || typeof value === 'boolean') {
            return null;
        }
        const number = Number(value);
        return Number.isFinite(number) && number >= 0 ? number : null;
    }

    function boundedPercent(value) {
        const number = nonNegativeNumber(value);
        return number !== null && number <= 100
            ? Math.round(number)
            : null;
    }

    function buildMetricSample(stats, sampledAt, cpuPercent, networkRates) {
        const loadOne = nonNegativeNumber(stats.load?.one);
        return Object.freeze({
            sampledAt: Number.isFinite(Number(sampledAt)) ? Number(sampledAt) : null,
            cpuPercent: boundedPercent(cpuPercent),
            memoryPercent: percent(stats.memory?.used_kib, stats.memory?.total_kib),
            swapPercent: percent(stats.swap?.used_kib, stats.swap?.total_kib),
            diskPercent: boundedPercent(stats.disk?.percent),
            loadOne,
            normalizedLoadPercent: loadOne === null
                ? null
                : percent(loadOne, stats.load?.cpu_count),
            receivedBps: nonNegativeNumber(networkRates?.received_bps),
            transmittedBps: nonNegativeNumber(networkRates?.transmitted_bps),
            processTotal: nonNegativeNumber(stats.processes?.total),
            processZombies: nonNegativeNumber(stats.processes?.zombies),
        });
    }

    function metricAvailability(state) {
        const stats = state?.stats || {};
        const availability = {
            cpu: boundedPercent(state?.cpuPercent) !== null,
            memory: percent(
                stats.memory?.used_kib,
                stats.memory?.total_kib,
            ) !== null,
            disk: (
                boundedPercent(stats.disk?.percent) !== null
                && percent(stats.disk?.used_kib, stats.disk?.total_kib) !== null
            ),
            os: typeof stats.os_name === 'string' && Boolean(stats.os_name.trim()),
            uptime: nonNegativeNumber(stats.uptime_seconds) !== null,
        };
        availability.any = Object.values(availability).some(Boolean);
        return availability;
    }

    function createController(options) {
        const socket = options.socket;
        const render = options.render || (() => {});
        const setIntervalFn = options.setIntervalFn || setInterval;
        const clearIntervalFn = options.clearIntervalFn || clearInterval;
        const setTimeoutFn = options.setTimeoutFn || setTimeout;
        const clearTimeoutFn = options.clearTimeoutFn || clearTimeout;
        const nowFn = options.nowFn || Date.now;

        let sessionId = null;
        let connected = false;
        let visible = true;
        let diagnosticsVisible = false;
        let intervalId = null;
        let responseTimeoutId = null;
        let retryTimeoutId = null;
        let pendingRequest = null;
        let requestCounter = 0;
        let failureCount = 0;
        let lastGood = null;
        const previousCpuBySession = new Map();
        const metricHistoryBySession = new Map();
        const previousNetworkBySession = new Map();
        const lastGoodBySession = new Map();
        const unsupportedSessions = new Set();
        const unsupportedDiagnosticsSessions = new Set();

        function currentState(status, extra = {}) {
            return {
                status,
                sessionId,
                failureCount,
                ...extra,
            };
        }

        function clearResponseTimeout() {
            if (responseTimeoutId !== null) {
                clearTimeoutFn(responseTimeoutId);
                responseTimeoutId = null;
            }
        }

        function clearPolling() {
            if (intervalId !== null) {
                clearIntervalFn(intervalId);
                intervalId = null;
            }
            clearResponseTimeout();
            if (retryTimeoutId !== null) {
                clearTimeoutFn(retryTimeoutId);
                retryTimeoutId = null;
            }
            pendingRequest = null;
        }

        function pauseRegularPolling() {
            if (intervalId !== null) {
                clearIntervalFn(intervalId);
                intervalId = null;
            }
        }

        function scheduleRetry() {
            if (retryTimeoutId !== null || unsupportedSessions.has(sessionId)) return;
            retryTimeoutId = setTimeoutFn(() => {
                retryTimeoutId = null;
                if (!visible || !connected || !sessionId || unsupportedSessions.has(sessionId)) {
                    return;
                }
                requestSample();
                if (intervalId === null) {
                    intervalId = setIntervalFn(requestSample, POLL_INTERVAL_MS);
                }
            }, BACKOFF_RETRY_MS);
        }

        function renderFailure(reason = 'transient', responseRequest = null) {
            if (reason === 'unsupported') {
                if (responseRequest?.includeDiagnostics) {
                    unsupportedDiagnosticsSessions.add(sessionId);
                    failureCount = 0;
                    render(currentState(lastGood ? 'ready' : 'loading', lastGood ? { ...lastGood } : {}));
                    requestSample();
                    return;
                }
                unsupportedSessions.add(sessionId);
                pauseRegularPolling();
                if (retryTimeoutId !== null) {
                    clearTimeoutFn(retryTimeoutId);
                    retryTimeoutId = null;
                }
                render(currentState('unavailable', lastGood ? { ...lastGood } : {}));
                return;
            }
            if (reason === 'busy') {
                render(currentState('stale', lastGood ? { ...lastGood } : {}));
                return;
            }
            failureCount += 1;
            const status = failureCount >= 3 ? 'unavailable' : 'stale';
            render(currentState(status, lastGood ? { ...lastGood } : {}));
            if (failureCount >= 3) {
                pauseRegularPolling();
                scheduleRetry();
            }
        }

        function requestSample() {
            if (
                !visible
                || !connected
                || !sessionId
                || pendingRequest
                || unsupportedSessions.has(sessionId)
            ) return;
            requestCounter += 1;
            const requestId = `insights-${requestCounter}`;
            pendingRequest = {
                sessionId,
                requestId,
                includeDiagnostics: diagnosticsVisible
                    && !unsupportedDiagnosticsSessions.has(sessionId),
            };
            const payload = {
                session_id: sessionId,
                request_id: requestId,
            };
            if (pendingRequest.includeDiagnostics) payload.include_diagnostics = true;
            socket.emit('request_session_insights', payload);
            responseTimeoutId = setTimeoutFn(() => {
                if (!pendingRequest || pendingRequest.requestId !== requestId) return;
                pendingRequest = null;
                responseTimeoutId = null;
                renderFailure();
            }, RESPONSE_TIMEOUT_MS);
        }

        function startPolling() {
            if (
                !visible
                || !connected
                || !sessionId
                || unsupportedSessions.has(sessionId)
            ) return;
            requestSample();
            intervalId = setIntervalFn(requestSample, POLL_INTERVAL_MS);
        }

        function handleResponse(payload) {
            if (!pendingRequest || !payload) return;
            if (
                payload.session_id !== pendingRequest.sessionId
                || payload.request_id !== pendingRequest.requestId
                || payload.session_id !== sessionId
            ) {
                return;
            }

            const responseRequest = pendingRequest;
            pendingRequest = null;
            clearResponseTimeout();
            if (!payload.success || !payload.stats) {
                renderFailure(payload.reason, responseRequest);
                return;
            }

            failureCount = 0;
            const stats = payload.stats;
            const previousCpu = previousCpuBySession.get(sessionId) || null;
            const cpuPercent = calculateCpuPercent(previousCpu, stats.cpu);
            if (Array.isArray(stats.cpu)) {
                previousCpuBySession.set(sessionId, stats.cpu.slice());
            }

            let networkRates = null;
            const sampledAt = nowFn();
            if (stats.network) {
                const networkSample = {
                    received_bytes: Number(stats.network.received_bytes),
                    transmitted_bytes: Number(stats.network.transmitted_bytes),
                    sampled_at: Number(sampledAt),
                };
                networkRates = calculateNetworkRates(
                    previousNetworkBySession.get(sessionId) || null,
                    networkSample,
                );
                if (
                    Number.isFinite(networkSample.received_bytes)
                    && Number.isFinite(networkSample.transmitted_bytes)
                    && Number.isFinite(networkSample.sampled_at)
                ) {
                    previousNetworkBySession.set(sessionId, networkSample);
                }
            }

            const metricHistory = metricHistoryBySession.get(sessionId) || [];
            metricHistory.push(buildMetricSample(stats, sampledAt, cpuPercent, networkRates));
            while (metricHistory.length > HISTORY_LIMIT) metricHistory.shift();
            metricHistoryBySession.set(sessionId, metricHistory);
            const cpuHistory = metricHistory
                .map(sample => sample.cpuPercent)
                .filter(value => value !== null);

            lastGood = {
                stats,
                cpuPercent,
                cpuHistory,
                metricHistory: metricHistory.slice(),
                networkRates,
            };
            lastGoodBySession.set(sessionId, lastGood);
            render(currentState('ready', { ...lastGood }));
            if (
                diagnosticsVisible
                && !responseRequest.includeDiagnostics
                && !unsupportedDiagnosticsSessions.has(sessionId)
            ) {
                requestSample();
            }
        }

        socket.on('session_insights', handleResponse);

        return {
            setSession(nextSessionId, isConnected) {
                clearPolling();
                sessionId = typeof nextSessionId === 'string' && nextSessionId
                    ? nextSessionId
                    : null;
                connected = Boolean(isConnected && sessionId);
                failureCount = 0;
                lastGood = sessionId ? lastGoodBySession.get(sessionId) || null : null;
                const unsupported = sessionId && unsupportedSessions.has(sessionId);
                render(currentState(
                    connected ? (unsupported ? 'unavailable' : 'loading') : 'disconnected',
                    lastGood ? { ...lastGood } : { metricHistory: [] },
                ));
                if (!unsupported) startPolling();
            },

            setVisible(nextVisible) {
                const normalized = Boolean(nextVisible);
                if (visible === normalized) return;
                visible = normalized;
                clearPolling();
                if (visible) {
                    render(currentState(
                        connected && unsupportedSessions.has(sessionId)
                            ? 'unavailable'
                            : (connected ? 'loading' : 'disconnected'),
                        lastGood ? { ...lastGood } : {},
                    ));
                    startPolling();
                }
            },

            setDiagnosticsVisible(nextVisible) {
                const normalized = Boolean(nextVisible);
                if (diagnosticsVisible === normalized) return;
                diagnosticsVisible = normalized;
                if (diagnosticsVisible) {
                    previousNetworkBySession.delete(sessionId);
                    requestSample();
                }
            },

            removeSession(removedSessionId) {
                if (typeof removedSessionId !== 'string' || !removedSessionId) return;
                previousCpuBySession.delete(removedSessionId);
                previousNetworkBySession.delete(removedSessionId);
                metricHistoryBySession.delete(removedSessionId);
                lastGoodBySession.delete(removedSessionId);
                unsupportedSessions.delete(removedSessionId);
                unsupportedDiagnosticsSessions.delete(removedSessionId);
                if (sessionId !== removedSessionId) return;
                clearPolling();
                sessionId = null;
                connected = false;
                failureCount = 0;
                lastGood = null;
                render(currentState('disconnected'));
            },

            destroy() {
                clearPolling();
                socket.off?.('session_insights', handleResponse);
            },
        };
    }

    return {
        POLL_INTERVAL_MS,
        RESPONSE_TIMEOUT_MS,
        BACKOFF_RETRY_MS,
        calculateCpuPercent,
        formatKib,
        severityForPercent,
        calculateNetworkRates,
        percent,
        metricAvailability,
        createController,
    };
}));
