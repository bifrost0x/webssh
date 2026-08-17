const assert = require('node:assert/strict');
const test = require('node:test');

const insights = require('../../static/js/session-insights.js');


function fakeRuntime(options = {}) {
    const emitted = [];
    const handlers = new Map();
    const intervals = new Map();
    const timeouts = new Map();
    let nextTimer = 1;
    const renders = [];

    const socket = {
        emit(event, payload) {
            emitted.push({ event, payload });
        },
        on(event, handler) {
            handlers.set(event, handler);
        },
        off(event, handler) {
            if (handlers.get(event) === handler) handlers.delete(event);
        },
    };
    const controller = insights.createController({
        socket,
        render: state => renders.push(state),
        setIntervalFn(callback, delay) {
            const id = nextTimer++;
            intervals.set(id, { callback, delay });
            return id;
        },
        clearIntervalFn(id) {
            intervals.delete(id);
        },
        setTimeoutFn(callback, delay) {
            const id = nextTimer++;
            timeouts.set(id, { callback, delay });
            return id;
        },
        clearTimeoutFn(id) {
            timeouts.delete(id);
        },
        nowFn: options.nowFn,
    });

    return { controller, emitted, handlers, intervals, timeouts, renders };
}


test('calculates CPU percent from Linux counter deltas without counting idle time', () => {
    assert.equal(
        insights.calculateCpuPercent(
            [100, 0, 50, 800, 20, 10, 5, 15],
            [130, 0, 70, 840, 30, 15, 10, 25],
        ),
        58,
    );
    assert.equal(insights.calculateCpuPercent(null, [1, 2, 3, 4]), null);
    assert.equal(
        insights.calculateCpuPercent([10, 10, 10, 10], [1, 1, 1, 1]),
        null,
    );
});

test('formats KiB values and maps visual thresholds', () => {
    assert.equal(insights.formatKib(1024), '1.0 MB');
    assert.equal(insights.formatKib(5 * 1024 * 1024), '5.0 GB');
    assert.equal(insights.severityForPercent(74), 'normal');
    assert.equal(insights.severityForPercent(75), 'warning');
    assert.equal(insights.severityForPercent(90), 'critical');
});

test('reports only telemetry sections with usable values', () => {
    assert.deepEqual(insights.metricAvailability({
        cpuPercent: null,
        stats: {
            memory: { total_kib: 4096, used_kib: 3072 },
            os_name: 'Appliance OS',
        },
    }), {
        cpu: false,
        memory: true,
        disk: false,
        os: true,
        uptime: false,
        any: true,
    });

    assert.equal(insights.metricAvailability({ stats: {} }).any, false);
});


test('requests immediately and repeats on an exact four second interval', () => {
    const runtime = fakeRuntime();

    runtime.controller.setSession('session-a', true);

    assert.equal(runtime.emitted.length, 1);
    assert.equal(runtime.emitted[0].event, 'request_session_insights');
    assert.equal(runtime.emitted[0].payload.session_id, 'session-a');
    assert.equal('include_diagnostics' in runtime.emitted[0].payload, false);
    assert.equal(runtime.intervals.size, 1);
    assert.equal([...runtime.intervals.values()][0].delay, 4000);
    assert.equal([...runtime.timeouts.values()][0].delay, 3500);

    const firstRequest = runtime.emitted[0].payload;
    runtime.handlers.get('session_insights')({
        success: true,
        session_id: 'session-a',
        request_id: firstRequest.request_id,
        stats: {
            cpu: [100, 0, 50, 850],
            memory: { total_kib: 1000, available_kib: 400, used_kib: 600 },
            disk: { total_kib: 2000, available_kib: 1500, used_kib: 500, percent: 25 },
            uptime_seconds: 3600,
            os_name: 'Debian GNU/Linux 13',
        },
    });

    [...runtime.intervals.values()][0].callback();
    assert.equal(runtime.emitted.length, 2);
});


test('requests expanded diagnostics only while the overlay is visible', () => {
    const runtime = fakeRuntime();
    runtime.controller.setSession('session-a', true);
    const firstRequest = runtime.emitted[0].payload;

    runtime.handlers.get('session_insights')({
        success: true,
        session_id: 'session-a',
        request_id: firstRequest.request_id,
        stats: {
            cpu: [100, 0, 50, 850],
            memory: { total_kib: 1000, available_kib: 400, used_kib: 600 },
            disk: { total_kib: 2000, available_kib: 1500, used_kib: 500, percent: 25 },
            uptime_seconds: 3600,
            os_name: 'Linux',
        },
    });

    runtime.controller.setDiagnosticsVisible(true);
    assert.equal(runtime.emitted.at(-1).payload.include_diagnostics, true);

    const expandedRequest = runtime.emitted.at(-1).payload;
    runtime.handlers.get('session_insights')({
        success: true,
        session_id: 'session-a',
        request_id: expandedRequest.request_id,
        stats: {
            cpu: [110, 0, 55, 900],
            memory: { total_kib: 1000, available_kib: 400, used_kib: 600 },
            disk: { total_kib: 2000, available_kib: 1500, used_kib: 500, percent: 25 },
            uptime_seconds: 3604,
            os_name: 'Linux',
        },
    });
    runtime.controller.setDiagnosticsVisible(false);
    [...runtime.intervals.values()][0].callback();

    assert.equal('include_diagnostics' in runtime.emitted.at(-1).payload, false);
});


test('derives network throughput and discards counter resets', () => {
    let now = 1000;
    const runtime = fakeRuntime({ nowFn: () => now });
    runtime.controller.setSession('session-a', true);

    function respond(receivedBytes, transmittedBytes) {
        const request = runtime.emitted.at(-1).payload;
        runtime.handlers.get('session_insights')({
            success: true,
            session_id: 'session-a',
            request_id: request.request_id,
            stats: {
                cpu: [100 + now, 0, 50, 850 + now],
                memory: { total_kib: 1000, available_kib: 400, used_kib: 600 },
                disk: { total_kib: 2000, available_kib: 1500, used_kib: 500, percent: 25 },
                uptime_seconds: 3600,
                os_name: 'Linux',
                network: {
                    received_bytes: receivedBytes,
                    transmitted_bytes: transmittedBytes,
                },
            },
        });
    }

    respond(10000, 5000);
    assert.equal(runtime.renders.at(-1).networkRates, null);

    now = 3000;
    [...runtime.intervals.values()][0].callback();
    respond(14000, 7000);
    assert.deepEqual(runtime.renders.at(-1).networkRates, {
        received_bps: 2000,
        transmitted_bps: 1000,
    });

    now = 5000;
    [...runtime.intervals.values()][0].callback();
    respond(100, 50);
    assert.equal(runtime.renders.at(-1).networkRates, null);
});


test('starts a fresh network baseline whenever diagnostics is reopened', () => {
    let now = 1000;
    const runtime = fakeRuntime({ nowFn: () => now });
    runtime.controller.setSession('session-a', true);
    runtime.controller.setDiagnosticsVisible(true);

    function respond(stats) {
        const request = runtime.emitted.at(-1).payload;
        runtime.handlers.get('session_insights')({
            success: true,
            session_id: 'session-a',
            request_id: request.request_id,
            stats: {
                cpu: [100, 0, 50, 850],
                memory: { total_kib: 1000, available_kib: 400, used_kib: 600 },
                disk: { total_kib: 2000, available_kib: 1500, used_kib: 500, percent: 25 },
                uptime_seconds: 3600,
                os_name: 'Linux',
                ...stats,
            },
        });
    }

    respond({});
    respond({ network: { received_bytes: 10000, transmitted_bytes: 5000 } });
    assert.equal(runtime.renders.at(-1).networkRates, null);

    runtime.controller.setDiagnosticsVisible(false);
    now = 61000;
    runtime.controller.setDiagnosticsVisible(true);
    respond({ network: { received_bytes: 70000, transmitted_bytes: 35000 } });

    assert.equal(runtime.renders.at(-1).networkRates, null);
});


test('never overlaps a pending request and ignores late responses', () => {
    const runtime = fakeRuntime();
    runtime.controller.setSession('session-a', true);
    const firstRequest = runtime.emitted[0].payload;

    [...runtime.intervals.values()][0].callback();
    assert.equal(runtime.emitted.length, 1);

    runtime.controller.setSession('session-b', true);
    assert.equal(runtime.emitted.length, 2);
    runtime.handlers.get('session_insights')({
        success: true,
        session_id: 'session-a',
        request_id: firstRequest.request_id,
        stats: {},
    });

    assert.equal(runtime.renders.at(-1).sessionId, 'session-b');
    assert.equal(runtime.renders.at(-1).status, 'loading');
});


test('pauses while hidden and resumes immediately for the same session', () => {
    const runtime = fakeRuntime();
    runtime.controller.setSession('session-a', true);
    runtime.controller.setVisible(false);

    assert.equal(runtime.intervals.size, 0);
    assert.equal(runtime.timeouts.size, 0);
    runtime.controller.setVisible(true);

    assert.equal(runtime.emitted.length, 2);
    assert.equal(runtime.intervals.size, 1);
});


test('marks one failed update stale and three consecutive failures unavailable', () => {
    const runtime = fakeRuntime();
    runtime.controller.setSession('session-a', true);

    function failCurrentRequest() {
        const request = runtime.emitted.at(-1).payload;
        runtime.handlers.get('session_insights')({
            success: false,
            session_id: 'session-a',
            request_id: request.request_id,
        });
    }

    failCurrentRequest();
    assert.equal(runtime.renders.at(-1).status, 'stale');
    [...runtime.intervals.values()][0].callback();
    failCurrentRequest();
    [...runtime.intervals.values()][0].callback();
    failCurrentRequest();

    assert.equal(runtime.renders.at(-1).status, 'unavailable');
});

test('stops probing a session after the server confirms metrics are unsupported', () => {
    const runtime = fakeRuntime();
    runtime.controller.setSession('switch-a', true);
    const request = runtime.emitted.at(-1).payload;

    runtime.handlers.get('session_insights')({
        success: false,
        reason: 'unsupported',
        session_id: 'switch-a',
        request_id: request.request_id,
    });

    assert.equal(runtime.intervals.size, 0);
    assert.equal(runtime.renders.at(-1).status, 'unavailable');
    runtime.controller.setSession('switch-a', true);
    assert.equal(runtime.emitted.length, 1);

    runtime.controller.removeSession('switch-a');
    runtime.controller.setSession('switch-a', true);
    assert.equal(runtime.emitted.length, 2);
});

test('keeps base telemetry polling when only expanded diagnostics are unsupported', () => {
    const runtime = fakeRuntime();
    runtime.controller.setSession('appliance-a', true);
    const baseRequest = runtime.emitted.at(-1).payload;
    runtime.handlers.get('session_insights')({
        success: true,
        session_id: 'appliance-a',
        request_id: baseRequest.request_id,
        stats: { memory: { total_kib: 1000, used_kib: 600 } },
    });

    runtime.controller.setDiagnosticsVisible(true);
    const expandedRequest = runtime.emitted.at(-1).payload;
    assert.equal(expandedRequest.include_diagnostics, true);
    runtime.handlers.get('session_insights')({
        success: false,
        reason: 'unsupported',
        session_id: 'appliance-a',
        request_id: expandedRequest.request_id,
    });

    const fallbackRequest = runtime.emitted.at(-1).payload;
    assert.notEqual(fallbackRequest.request_id, expandedRequest.request_id);
    assert.equal('include_diagnostics' in fallbackRequest, false);
    assert.equal(runtime.intervals.size, 1);
    assert.equal(runtime.renders.at(-1).status, 'ready');
    const emittedBeforeFallbackResponse = runtime.emitted.length;
    runtime.handlers.get('session_insights')({
        success: true,
        session_id: 'appliance-a',
        request_id: fallbackRequest.request_id,
        stats: { memory: { total_kib: 1000, used_kib: 600 } },
    });
    assert.equal(runtime.emitted.length, emittedBeforeFallbackResponse);
});

test('keeps the previous CPU baseline across partial samples without CPU counters', () => {
    const runtime = fakeRuntime();
    runtime.controller.setSession('session-a', true);

    function respond(stats) {
        const request = runtime.emitted.at(-1).payload;
        runtime.handlers.get('session_insights')({
            success: true,
            session_id: 'session-a',
            request_id: request.request_id,
            stats,
        });
    }

    respond({ cpu: [100, 0, 50, 850] });
    [...runtime.intervals.values()][0].callback();
    respond({ memory: { total_kib: 1000, used_kib: 500 } });
    [...runtime.intervals.values()][0].callback();
    respond({ cpu: [110, 0, 60, 880] });

    assert.equal(runtime.renders.at(-1).cpuPercent, 40);
});

test('backs off regular polling after three transient failures', () => {
    const runtime = fakeRuntime();
    runtime.controller.setSession('iot-a', true);

    function failCurrentRequest() {
        const request = runtime.emitted.at(-1).payload;
        runtime.handlers.get('session_insights')({
            success: false,
            reason: 'transient',
            session_id: 'iot-a',
            request_id: request.request_id,
        });
    }

    failCurrentRequest();
    [...runtime.intervals.values()][0].callback();
    failCurrentRequest();
    [...runtime.intervals.values()][0].callback();
    failCurrentRequest();

    assert.equal(runtime.intervals.size, 0);
    assert.equal(
        [...runtime.timeouts.values()].some(timer => timer.delay === 60000),
        true,
    );
});


test('keeps the newest 150 structured samples per session', () => {
    let now = 0;
    const runtime = fakeRuntime({ nowFn: () => now });
    runtime.controller.setSession('session-a', true);

    for (let index = 0; index < 151; index += 1) {
        const request = runtime.emitted.at(-1).payload;
        runtime.handlers.get('session_insights')({
            success: true,
            session_id: 'session-a',
            request_id: request.request_id,
            stats: {
                cpu: [100 + index * 10, 0, 50 + index * 5, 850 + index * 5],
                memory: { total_kib: 1000, available_kib: 400, used_kib: 600 },
                disk: { total_kib: 2000, available_kib: 1500, used_kib: 500, percent: 25 },
                uptime_seconds: 3600 + index * 4,
                os_name: 'Linux',
            },
        });
        now += 1;
        [...runtime.intervals.values()][0].callback();
    }

    const state = runtime.renders.at(-1);
    assert.equal(state.metricHistory.length, 150);
    assert.equal(state.cpuHistory.length, 150);
    assert.equal(state.metricHistory[0].sampledAt, 1);
    assert.equal(state.metricHistory.at(-1).sampledAt, 150);
});

test('stores immutable, normalized metric samples including null gaps', () => {
    let now = 1000;
    const runtime = fakeRuntime({ nowFn: () => now });
    runtime.controller.setSession('session-a', true);

    function respond(stats) {
        const request = runtime.emitted.at(-1).payload;
        runtime.handlers.get('session_insights')({
            success: true,
            session_id: 'session-a',
            request_id: request.request_id,
            stats,
        });
    }

    respond({
        cpu: [100, 0, 50, 850],
        network: { received_bytes: 0, transmitted_bytes: 0 },
    });
    now = 5000;
    [...runtime.intervals.values()][0].callback();
    respond({
        cpu: [110, 0, 60, 880],
        memory: { used_kib: 600, total_kib: 1000 },
        swap: { used_kib: 25, total_kib: 100 },
        disk: { percent: 61 },
        load: { one: 1.25, cpu_count: 8 },
        network: { received_bytes: 8192, transmitted_bytes: 4096 },
        processes: { total: 215, zombies: 1 },
    });

    assert.deepEqual(runtime.renders.at(-1).metricHistory.at(-1), {
        sampledAt: 5000,
        cpuPercent: 40,
        memoryPercent: 60,
        swapPercent: 25,
        diskPercent: 61,
        loadOne: 1.25,
        normalizedLoadPercent: 16,
        receivedBps: 2048,
        transmittedBps: 1024,
        processTotal: 215,
        processZombies: 1,
    });

    now = 9000;
    [...runtime.intervals.values()][0].callback();
    respond({
        cpu: [120, 0, 70, 910],
        memory: { used_kib: 'bad', total_kib: 0 },
        swap: { used_kib: -1, total_kib: 100 },
        disk: { percent: 'bad' },
        load: { one: 'bad', cpu_count: 0 },
        network: { received_bytes: 1, transmitted_bytes: 1 },
        processes: { total: 'bad', zombies: -1 },
    });

    assert.deepEqual(runtime.renders.at(-1).metricHistory.at(-1), {
        sampledAt: 9000,
        cpuPercent: 40,
        memoryPercent: null,
        swapPercent: null,
        diskPercent: null,
        loadOne: null,
        normalizedLoadPercent: null,
        receivedBps: null,
        transmittedBps: null,
        processTotal: null,
        processZombies: null,
    });
});

test('restores isolated session history and removes only the closed session state', () => {
    let now = 1000;
    const runtime = fakeRuntime({ nowFn: () => now });

    function respond(sessionId, stats) {
        const request = runtime.emitted.at(-1).payload;
        runtime.handlers.get('session_insights')({
            success: true,
            session_id: sessionId,
            request_id: request.request_id,
            stats,
        });
    }

    runtime.controller.setSession('session-a', true);
    respond('session-a', {
        cpu: [100, 0, 50, 850],
        network: { received_bytes: 0, transmitted_bytes: 0 },
    });
    now = 5000;
    [...runtime.intervals.values()][0].callback();
    respond('session-a', {
        cpu: [110, 0, 60, 880],
        network: { received_bytes: 8192, transmitted_bytes: 4096 },
    });
    const aHistory = runtime.renders.at(-1).metricHistory;

    runtime.controller.setSession('session-b', true);
    respond('session-b', { cpu: [10, 0, 5, 85] });
    assert.equal(runtime.renders.at(-1).metricHistory.length, 1);

    runtime.controller.setSession('session-a', true);
    assert.deepEqual(runtime.renders.at(-1).metricHistory, aHistory);
    runtime.controller.setDiagnosticsVisible(false);
    runtime.controller.setDiagnosticsVisible(true);
    assert.deepEqual(runtime.renders.at(-1).metricHistory, aHistory);

    runtime.controller.removeSession('session-a');
    runtime.controller.setSession('session-a', true);
    assert.equal(runtime.renders.at(-1).metricHistory.length, 0);
    runtime.controller.setSession('session-b', true);
    assert.equal(runtime.renders.at(-1).metricHistory.length, 1);
});
