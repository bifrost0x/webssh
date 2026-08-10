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
        const numerator = Number(used);
        const denominator = Number(total);
        if (!Number.isFinite(numerator) || !Number.isFinite(denominator) || denominator <= 0) return null;
        return Math.max(0, Math.min(100, Math.round((numerator / denominator) * 100)));
    }

    function nonNegativeNumber(value) {
        const number = Number(value);
        return Number.isFinite(number) && number >= 0 ? number : null;
    }

    function boundedPercent(value) {
        const number = Number(value);
        return Number.isFinite(number) && number >= 0 && number <= 100
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
        let pendingRequest = null;
        let requestCounter = 0;
        let failureCount = 0;
        let lastGood = null;
        const previousCpuBySession = new Map();
        const metricHistoryBySession = new Map();
        const previousNetworkBySession = new Map();
        const lastGoodBySession = new Map();

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
            pendingRequest = null;
        }

        function renderFailure() {
            failureCount += 1;
            const status = failureCount >= 3 ? 'unavailable' : 'stale';
            render(currentState(status, lastGood ? { ...lastGood } : {}));
        }

        function requestSample() {
            if (!visible || !connected || !sessionId || pendingRequest) return;
            requestCounter += 1;
            const requestId = `insights-${requestCounter}`;
            pendingRequest = {
                sessionId,
                requestId,
                includeDiagnostics: diagnosticsVisible,
            };
            const payload = {
                session_id: sessionId,
                request_id: requestId,
            };
            if (diagnosticsVisible) payload.include_diagnostics = true;
            socket.emit('request_session_insights', payload);
            responseTimeoutId = setTimeoutFn(() => {
                if (!pendingRequest || pendingRequest.requestId !== requestId) return;
                pendingRequest = null;
                responseTimeoutId = null;
                renderFailure();
            }, RESPONSE_TIMEOUT_MS);
        }

        function startPolling() {
            if (!visible || !connected || !sessionId) return;
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
                renderFailure();
                return;
            }

            failureCount = 0;
            const stats = payload.stats;
            const previousCpu = previousCpuBySession.get(sessionId) || null;
            const cpuPercent = calculateCpuPercent(previousCpu, stats.cpu);
            previousCpuBySession.set(sessionId, Array.isArray(stats.cpu) ? stats.cpu.slice() : null);

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
            if (diagnosticsVisible && !responseRequest.includeDiagnostics) {
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
                render(currentState(
                    connected ? 'loading' : 'disconnected',
                    lastGood ? { ...lastGood } : {},
                ));
                startPolling();
            },

            setVisible(nextVisible) {
                const normalized = Boolean(nextVisible);
                if (visible === normalized) return;
                visible = normalized;
                clearPolling();
                if (visible) {
                    render(currentState(
                        connected ? 'loading' : 'disconnected',
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
        calculateCpuPercent,
        formatKib,
        severityForPercent,
        calculateNetworkRates,
        percent,
        createController,
    };
}));
