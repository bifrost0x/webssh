const assert = require('node:assert/strict');
const test = require('node:test');

const diagnostics = require('../../static/js/session-diagnostics.js');


function fakeElement(tagName = 'div') {
    const classes = new Set();
    const attributes = new Map();
    const listeners = new Map();
    return {
        tagName: tagName.toUpperCase(),
        children: [],
        parentNode: null,
        hidden: false,
        disabled: false,
        textContent: '',
        dataset: {},
        classList: {
            add(...values) { values.forEach(value => classes.add(value)); },
            remove(...values) { values.forEach(value => classes.delete(value)); },
            contains(value) { return classes.has(value); },
            toggle(value, force) {
                const next = force === undefined ? !classes.has(value) : Boolean(force);
                if (next) classes.add(value);
                else classes.delete(value);
                return next;
            },
        },
        appendChild(child) {
            child.parentNode?.removeChild?.(child);
            child.parentNode = this;
            this.children.push(child);
            return child;
        },
        removeChild(child) {
            this.children = this.children.filter(candidate => candidate !== child);
            child.parentNode = null;
        },
        setAttribute(name, value) { attributes.set(name, String(value)); },
        getAttribute(name) { return attributes.get(name) ?? null; },
        removeAttribute(name) { attributes.delete(name); },
        addEventListener(type, handler) { listeners.set(type, handler); },
        removeEventListener(type, handler) {
            if (listeners.get(type) === handler) listeners.delete(type);
        },
        click() { listeners.get('click')?.({ target: this }); },
        querySelectorAll() { return []; },
    };
}


function createDiagnosticsLayoutHarness() {
    const ids = new Map();
    const body = fakeElement('body');
    const mount = fakeElement('section');
    const overlay = fakeElement('div');
    const drawer = fakeElement('section');
    const trigger = fakeElement('button');
    const backdrop = fakeElement('button');
    const close = fakeElement('button');
    const expand = fakeElement('button');
    const refresh = fakeElement('button');
    overlay.classList.add('hidden');
    overlay.appendChild(backdrop);
    overlay.appendChild(drawer);
    drawer.appendChild(expand);
    drawer.appendChild(close);
    mount.appendChild(overlay);
    body.appendChild(mount);
    [
        ['contextDiagnosticsTab', trigger],
        ['contextDiagnosticsPanel', mount],
        ['sessionDiagnosticsOverlay', overlay],
        ['sessionDiagnosticsBackdrop', backdrop],
        ['sessionDiagnosticsClose', close],
        ['sessionDiagnosticsExpand', expand],
        ['sessionDiagnosticsRefresh', refresh],
    ].forEach(([id, element]) => ids.set(id, element));
    const documentRef = {
        body,
        createElement: fakeElement,
        getElementById(id) { return ids.get(id) || null; },
        querySelector(selector) {
            return selector === '.session-diagnostics-drawer' ? drawer : null;
        },
    };
    const windowRef = {
        document: documentRef,
        addEventListener() {},
        removeEventListener() {},
        requestAnimationFrame(callback) { callback(); return 1; },
        cancelAnimationFrame() {},
    };
    return {
        body, mount, overlay, drawer, trigger, backdrop, close, expand,
        controller: diagnostics.createController({
            document: documentRef,
            window: windowRef,
        }),
    };
}


function coreState(extraStats = {}, history = []) {
    return {
        status: 'ready',
        sessionId: 'session-a',
        cpuPercent: 42.25,
        networkRates: { received_bps: 2048, transmitted_bps: 1024 },
        metricHistory: history,
        stats: {
            cpu: [10, 0, 5, 85],
            memory: { total_kib: 1000, available_kib: 400, used_kib: 600 },
            disk: { total_kib: 2000, available_kib: 1500, used_kib: 500, percent: 25 },
            load: { one: 1.25, five: 0.75, fifteen: 0.5, cpu_count: 8 },
            swap: { total_kib: 400, available_kib: 300, used_kib: 100 },
            network: { received_bytes: 5000, transmitted_bytes: 2500 },
            uptime_seconds: 3600,
            os_name: 'Debian GNU/Linux 13',
            ...extraStats,
        },
    };
}


function inventoryState(overrides = {}) {
    return {
        status: 'ready',
        sessionId: 'session-a',
        sampledAt: 1786350000,
        permissionDenied: [],
        inventory: {
            systemd: {
                state: 'degraded', total: 5, active: 2, failed: 1,
                returned: 4, truncated: true,
                services: [
                    { unit: 'nginx.service', load: 'loaded', active: 'active', sub: 'running', description: 'Web server' },
                    { unit: 'backup.service', load: 'loaded', active: 'failed', sub: 'failed', description: 'Nightly backup' },
                    { unit: 'cron.service', load: 'loaded', active: 'inactive', sub: 'dead', description: 'Scheduler' },
                    { unit: 'masked.service', load: 'masked', active: 'maintenance', sub: 'dead', description: 'Maintenance unit' },
                ],
            },
            docker: {
                version: '27.5.1', total: 3, running: 1,
                returned: 2, truncated: true,
                containers: [
                    { name: 'webssh', status: 'Up 3 hours (healthy)' },
                    { name: 'worker', status: 'Exited (1)' },
                ],
            },
        },
        ...overrides,
    };
}


test('builds numeric resource values separately from formatted labels', () => {
    const model = diagnostics.buildViewModel(
        coreState(),
        { username: 'ops', host: 'edge-01.example' },
        inventoryState(),
    );

    assert.equal(model.available, true);
    assert.equal(model.host, 'ops@edge-01.example');
    assert.equal(model.resources.cpu.percent, 42.25);
    assert.equal(model.resources.cpu.label, '42.3%');
    assert.equal(model.resources.memory.percent, 60);
    assert.equal(model.resources.memory.label, '60.0%');
    assert.equal(model.resources.disk.percent, 25);
    assert.equal(model.resources.load.percent, 15.625);
    assert.equal(model.resources.load.label, '15.6%');
    assert.equal(model.secondary.swap.percent, 25);
    assert.equal(model.secondary.swap.label, '25.0%');
});


test('retains 150 pressure and network chart samples including null gaps', () => {
    const history = Array.from({ length: 160 }, (_, index) => ({
        cpuPercent: index === 159 ? null : index % 100,
        memoryPercent: index % 2 ? null : 60,
        diskPercent: 25,
        normalizedLoadPercent: index % 3 ? 12 : null,
        receivedBps: index % 4 ? index * 10 : null,
        transmittedBps: index % 5 ? index * 5 : null,
    }));
    const model = diagnostics.buildViewModel(coreState({}, history), null, inventoryState());

    assert.equal(model.charts.pressureHistory.length, 150);
    assert.equal(model.charts.networkHistory.length, 150);
    assert.equal(model.charts.pressureHistory.at(-1).cpuPercent, null);
    assert.equal(model.charts.pressureHistory.at(-1).memoryPercent, null);
    assert.equal(model.charts.networkHistory.at(-1).receivedBps, 1590);
    assert.equal(model.charts.networkHistory.at(-1).transmittedBps, 795);
});


test('builds bounded process rows with numeric proportional bars and formatted labels', () => {
    const rows = Array.from({ length: 8 }, (_, index) => ({
        pid: 100 + index,
        user: 'ops',
        command: `worker-${index}`,
        cpu_percent: index === 0 ? 132.5 : 30 - index,
        memory_percent: 5 + index,
    }));
    const model = diagnostics.buildViewModel(coreState({
        processes: { total: 215, zombies: 2, top_cpu: rows, top_memory: rows.slice().reverse() },
    }), null, inventoryState());

    assert.equal(model.processes.topCpu.length, 5);
    assert.equal(model.processes.topMemory.length, 5);
    assert.equal(model.processes.topCpu[0].percent, 132.5);
    assert.equal(model.processes.topCpu[0].barPercent, 100);
    assert.equal(model.processes.topCpu[0].label, '132.5%');
    assert.equal(model.processes.topMemory[0].percent, 12);
    assert.equal(model.processes.topMemory[0].barPercent, 12);
});


test('builds filtered systemd and Docker summaries with distribution and truncation', () => {
    const model = diagnostics.buildViewModel(
        coreState(), null, inventoryState(),
        { systemdStatus: 'inactive', systemdQuery: 'unit', dockerQuery: 'work' },
    );

    assert.deepEqual(
        {
            total: model.systemd.total,
            active: model.systemd.active,
            failed: model.systemd.failed,
            returned: model.systemd.returned,
            truncated: model.systemd.truncated,
        },
        { total: 5, active: 2, failed: 1, returned: 4, truncated: true },
    );
    assert.deepEqual(model.systemd.rows.map(row => row.unit), ['masked.service']);
    assert.equal(model.systemd.inactive, 2);
    assert.equal(model.systemd.truncationLabel, 'Showing 4 of 5 services');
    assert.equal(model.docker.running, 1);
    assert.equal(model.docker.total, 3);
    assert.equal(model.docker.returned, 2);
    assert.equal(model.docker.truncated, true);
    assert.deepEqual(model.docker.rows.map(row => row.name), ['worker']);
    assert.equal(model.docker.truncationLabel, 'Showing 2 of 3 containers');
});


test('keeps cached inventory visible as stale with its original timestamp', () => {
    const stale = inventoryState({ status: 'stale' });
    const model = diagnostics.buildViewModel(coreState(), null, stale);

    assert.equal(model.inventory.status, 'stale');
    assert.equal(model.inventory.stale, true);
    assert.equal(model.inventory.sampledAt, 1786350000);
    assert.ok(model.systemd);
    assert.ok(model.docker);
});


test('permission scope hides only the affected inventory section', () => {
    const denied = inventoryState({
        permissionDenied: ['docker'],
        inventory: { systemd: inventoryState().inventory.systemd },
    });
    const model = diagnostics.buildViewModel(coreState(), null, denied);

    assert.ok(model.systemd);
    assert.equal(model.docker, null);
    assert.deepEqual(model.permissionNotices, [
        'Docker is installed, but this SSH user cannot access the Docker daemon.',
    ]);
});


test('never mixes cached inventory into a different active session', () => {
    const otherSessionState = coreState();
    otherSessionState.sessionId = 'session-b';
    const model = diagnostics.buildViewModel(otherSessionState, null, inventoryState());

    assert.equal(model.systemd, null);
    assert.equal(model.docker, null);
    assert.equal(model.inventory.sampledAt, null);
});


test('keeps hostile remote labels as plain model strings without markup generation', () => {
    const hostileInventory = inventoryState();
    hostileInventory.inventory.systemd.services[0] = {
        unit: '<img src=x onerror=alert(1)>.service',
        load: '<b>loaded</b>', active: 'active', sub: '<svg/onload=alert(1)>',
        description: '<script>alert(1)</script>',
    };
    hostileInventory.inventory.docker.containers[0] = {
        name: '<img src=x>', status: '<strong>Up</strong>',
    };
    const model = diagnostics.buildViewModel(coreState(), null, hostileInventory);

    assert.equal(model.systemd.rows[0].unit, '<img src=x onerror=alert(1)>.service');
    assert.equal(model.systemd.rows[0].description, '<script>alert(1)</script>');
    assert.equal(model.docker.rows[0].name, '<img src=x>');
    assert.equal(model.docker.rows[0].status, '<strong>Up</strong>');
    assert.equal(Object.hasOwn(model.systemd.rows[0], 'html'), false);
});


test('returns an unavailable model without telemetry or a connected session', () => {
    const model = diagnostics.buildViewModel(
        { status: 'disconnected', sessionId: null }, null,
        { status: 'disconnected', inventory: null },
    );

    assert.equal(model.available, false);
    assert.equal(model.host, 'No active session');
    assert.equal(model.systemd, null);
    assert.equal(model.docker, null);
    assert.deepEqual(model.permissionNotices, []);
});

test('translates generated diagnostics copy without changing remote values', () => {
    const translated = {
        'workspace.noActiveSession': 'Keine aktive Sitzung',
        'diagnostics.statusLive': 'Live-Daten',
        'diagnostics.currentUtilization': 'Aktuelle Auslastung',
        'diagnostics.showingServices': '{returned} von {total} Diensten',
        'diagnostics.showingContainers': '{returned} von {total} Containern',
        'diagnostics.permissionDocker': 'Docker-Zugriff eingeschränkt',
        'diagnostics.severityNormal': 'Normalbereich',
    };
    const translate = key => translated[key] || key;
    const denied = inventoryState({ permissionDenied: ['docker'] });
    const model = diagnostics.buildViewModel(
        coreState(),
        null,
        denied,
        {},
        translate,
    );

    assert.equal(model.host, 'Keine aktive Sitzung');
    assert.equal(model.status, 'Live-Daten');
    assert.equal(model.resources.cpu.detail, 'Aktuelle Auslastung');
    assert.equal(model.resources.cpu.severityLabel, 'Normalbereich');
    assert.equal(model.systemd.truncationLabel, '4 von 5 Diensten');
    assert.deepEqual(model.permissionNotices, ['Docker-Zugriff eingeschränkt']);
});

test('keeps diagnostics openable for a connected session before the first sample', () => {
    assert.equal(
        diagnostics.canOpenDiagnostics(
            { status: 'loading', sessionId: 'session-a', stats: null },
            { connected: true },
        ),
        true,
    );
    assert.equal(
        diagnostics.canOpenDiagnostics(
            { status: 'disconnected', sessionId: 'session-a', stats: null },
            { connected: false },
        ),
        false,
    );
});

test('keeps the embedded diagnostics context available only for a connected session', () => {
    assert.deepEqual(
        diagnostics.contextState(
            { status: 'loading', sessionId: 'session-a', stats: null },
            { connected: true },
            true,
        ),
        { available: true, open: true },
    );
    assert.deepEqual(
        diagnostics.contextState(
            { status: 'disconnected', sessionId: 'session-a', stats: null },
            { connected: false },
            true,
        ),
        { available: false, open: false },
    );
});

test('partial telemetry omits empty diagnostic cards and pressure chart', () => {
    const model = diagnostics.buildViewModel({
        status: 'ready',
        sessionId: 'switch-a',
        cpuPercent: null,
        metricHistory: [],
        stats: {
            memory: { total_kib: 4096, available_kib: 1024, used_kib: 3072 },
        },
    });

    assert.equal(model.available, true);
    assert.equal(model.resources.cpu, null);
    assert.equal(model.resources.memory.percent, 75);
    assert.equal(model.hasPressureHistory, false);
});

test('expands embedded diagnostics into the existing right-side overlay and restores it', () => {
    const harness = createDiagnosticsLayoutHarness();
    harness.trigger.disabled = false;
    harness.controller.setOpen(true);

    harness.expand.click();

    assert.equal(harness.overlay.parentNode, harness.body);
    assert.equal(harness.body.classList.contains('session-diagnostics-open'), true);
    assert.equal(harness.drawer.getAttribute('role'), 'dialog');
    assert.equal(harness.drawer.getAttribute('aria-modal'), 'true');
    assert.equal(harness.backdrop.hidden, false);
    assert.equal(harness.close.hidden, false);
    assert.equal(harness.controller.isExpanded(), true);

    harness.close.click();

    assert.equal(harness.overlay.parentNode, harness.mount);
    assert.equal(harness.body.classList.contains('session-diagnostics-open'), false);
    assert.equal(harness.drawer.getAttribute('role'), 'region');
    assert.equal(harness.drawer.getAttribute('aria-modal'), null);
    assert.equal(harness.backdrop.hidden, true);
    assert.equal(harness.close.hidden, true);
    assert.equal(harness.controller.isExpanded(), false);
});
