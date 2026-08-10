const assert = require('node:assert/strict');
const test = require('node:test');

const diagnostics = require('../../static/js/session-diagnostics.js');


function coreState(extraStats = {}) {
    return {
        status: 'ready',
        sessionId: 'session-a',
        cpuPercent: 42,
        networkRates: null,
        stats: {
            cpu: [10, 0, 5, 85],
            memory: { total_kib: 1000, available_kib: 400, used_kib: 600 },
            disk: { total_kib: 2000, available_kib: 1500, used_kib: 500, percent: 25 },
            uptime_seconds: 3600,
            os_name: 'Debian GNU/Linux 13',
            ...extraStats,
        },
    };
}


test('omits unsupported optional sections instead of creating empty cards', () => {
    const model = diagnostics.buildViewModel(
        coreState(),
        { username: 'ops', host: 'edge-01.example' },
    );

    assert.equal(model.available, true);
    assert.equal(model.host, 'ops@edge-01.example');
    assert.equal(model.sections.load, null);
    assert.equal(model.sections.swap, null);
    assert.equal(model.sections.network, null);
    assert.equal(model.sections.processes, null);
    assert.equal(model.sections.systemd, null);
    assert.equal(model.sections.docker, null);
    assert.deepEqual(model.permissionNotices, []);
});


test('builds bounded display data for supported diagnostics', () => {
    const processRows = Array.from({ length: 8 }, (_, index) => ({
        pid: 100 + index,
        user: 'ops',
        command: `worker-${index}`,
        cpu_percent: 30 - index,
        memory_percent: 5 + index,
    }));
    const state = coreState({
        load: { one: 1.25, five: 0.75, fifteen: 0.5, cpu_count: 8 },
        swap: { total_kib: 2048, available_kib: 1024, used_kib: 1024 },
        network: { received_bytes: 5000, transmitted_bytes: 2500 },
        processes: {
            total: 215,
            zombies: 2,
            top_cpu: processRows,
            top_memory: processRows.slice().reverse(),
        },
        systemd: {
            state: 'degraded',
            running: 41,
            failed: 1,
            failed_units: ['backup.service'],
        },
        docker: {
            version: '27.5.1',
            running: 3,
            total: 5,
            containers: [
                { name: 'webssh', status: 'Up 3 hours (healthy)' },
                { name: 'redis', status: 'Up 3 hours' },
            ],
        },
    });
    state.networkRates = { received_bps: 2048, transmitted_bps: 1024 };

    const model = diagnostics.buildViewModel(state, { username: 'ops', host: 'edge' });

    assert.equal(model.sections.load.one, '1.25');
    assert.equal(model.sections.swap.used, '1.0 MB');
    assert.equal(model.sections.network.received, '2.0 KB/s');
    assert.equal(model.sections.network.transmitted, '1.0 KB/s');
    assert.equal(model.sections.processes.topCpu.length, 5);
    assert.equal(model.sections.processes.topMemory.length, 5);
    assert.equal(model.sections.systemd.failedUnits[0], 'backup.service');
    assert.equal(model.sections.docker.containers[0].name, 'webssh');
});


test('surfaces only permission failures with scoped user-facing notices', () => {
    const model = diagnostics.buildViewModel(coreState({
        permission_denied: ['docker', 'processes', 'unknown', 'docker'],
    }), null);

    assert.deepEqual(model.permissionNotices, [
        'Docker is installed, but this SSH user cannot access the Docker daemon.',
        'Process details are restricted for this SSH user.',
    ]);
    assert.equal(model.sections.docker, null);
    assert.equal(model.sections.processes, null);
});


test('returns an unavailable model without telemetry or a connected session', () => {
    const model = diagnostics.buildViewModel(
        { status: 'disconnected', sessionId: null },
        null,
    );

    assert.equal(model.available, false);
    assert.equal(model.host, 'No active session');
    assert.deepEqual(model.permissionNotices, []);
});
