const assert = require('node:assert/strict');
const test = require('node:test');

const inventory = require('../../static/js/session-runtime-inventory.js');

function fakeRuntime() {
    const emitted = [];
    const handlers = new Map();
    const timers = new Map();
    const renders = [];
    let nextTimer = 1;
    const socket = {
        emit(event, payload) { emitted.push({ event, payload }); },
        on(event, handler) { handlers.set(event, handler); },
        off(event, handler) {
            if (handlers.get(event) === handler) handlers.delete(event);
        },
    };
    const controller = inventory.createController({
        socket,
        render: state => renders.push(state),
        setTimeoutFn(callback, delay) {
            const id = nextTimer++;
            timers.set(id, { callback, delay });
            return id;
        },
        clearTimeoutFn(id) { timers.delete(id); },
    });
    return { controller, emitted, handlers, timers, renders };
}

const services = [
    { unit: 'nginx.service', active: 'active', description: 'Nginx web server' },
    { unit: 'worker.service', active: 'failed', description: 'Background worker' },
    { unit: 'cron.service', active: 'inactive', description: 'Cron daemon' },
];
const containers = [
    { name: 'web', status: 'Up 3 hours' },
    { name: 'worker', status: 'Exited (1)' },
    { name: 'cache', status: 'Up 1 hour' },
];

test('filters service and container views without mutating their source arrays', () => {
    const originalServices = structuredClone(services);
    const originalContainers = structuredClone(containers);
    assert.equal(inventory.filterServices(services, 'all').length, 3);
    assert.deepEqual(inventory.filterServices(services, 'active').map(row => row.unit), ['nginx.service']);
    assert.deepEqual(inventory.filterServices(services, 'failed').map(row => row.unit), ['worker.service']);
    assert.deepEqual(inventory.filterServices(services, 'inactive').map(row => row.unit), ['cron.service']);
    assert.deepEqual(inventory.filterServices(services, 'WEB').map(row => row.unit), ['nginx.service']);
    assert.deepEqual(inventory.filterServices(services, 'background').map(row => row.unit), ['worker.service']);
    assert.deepEqual(inventory.filterContainers(containers, 'WORK').map(row => row.name), ['worker']);
    assert.deepEqual(inventory.filterContainers(containers, 'up').map(row => row.name), ['web', 'cache']);
    assert.deepEqual(services, originalServices);
    assert.deepEqual(containers, originalContainers);
});

test('builds and copies only allowlisted systemd commands', async () => {
    assert.equal(
        inventory.buildSystemdCommand('restart', 'nginx.service'),
        'sudo systemctl restart -- nginx.service',
    );
    assert.equal(inventory.buildSystemdCommand('enable', 'nginx.service'), null);
    assert.equal(inventory.buildSystemdCommand('restart', 'nginx.service;reboot'), null);
    const copied = [];
    assert.equal(
        await inventory.copySystemdCommand('start', 'api@1.service', value => copied.push(value)),
        'sudo systemctl start -- api@1.service',
    );
    assert.deepEqual(copied, ['sudo systemctl start -- api@1.service']);
    assert.equal(await inventory.copySystemdCommand('enable', 'nginx.service', value => copied.push(value)), null);
    assert.deepEqual(copied, ['sudo systemctl start -- api@1.service']);
});

test('correlates a single connected inventory request and refreshes after resolution', () => {
    const runtime = fakeRuntime();
    runtime.controller.setSession('session-a', true);
    runtime.controller.setOpen(true);
    assert.equal(runtime.emitted.length, 1);
    assert.equal(runtime.emitted[0].event, 'request_session_runtime_inventory');
    assert.equal(runtime.emitted[0].payload.request_id, 'runtime-inventory-1');
    runtime.controller.refresh();
    assert.equal(runtime.emitted.length, 1);

    runtime.handlers.get('session_runtime_inventory')({
        success: true,
        session_id: 'session-a',
        request_id: 'runtime-inventory-1',
        sampled_at: 5000,
        systemd: { services: [] },
    });
    runtime.controller.refresh();
    assert.equal(runtime.emitted.length, 2);
    assert.equal(runtime.emitted.at(-1).payload.request_id, 'runtime-inventory-2');
});

test('uses cached inventory on reopen while requesting a fresh snapshot', () => {
    const runtime = fakeRuntime();
    runtime.controller.setSession('session-a', true);
    runtime.controller.setOpen(true);
    runtime.handlers.get('session_runtime_inventory')({
        success: true, session_id: 'session-a', request_id: 'runtime-inventory-1', sampled_at: 11,
        systemd: { services: [] }, docker: { containers: [] },
    });
    runtime.controller.setOpen(false);
    runtime.controller.setOpen(true);
    assert.equal(runtime.renders.at(-1).status, 'ready');
    assert.deepEqual(runtime.renders.at(-1).inventory, { systemd: { services: [] }, docker: { containers: [] } });
    assert.equal(runtime.emitted.length, 2);
});

test('ignores mismatched and late responses', () => {
    const runtime = fakeRuntime();
    runtime.controller.setSession('session-a', true);
    runtime.controller.setOpen(true);
    runtime.handlers.get('session_runtime_inventory')({
        success: true, session_id: 'session-b', request_id: 'runtime-inventory-1', systemd: { services: [] },
    });
    assert.equal(runtime.controller.getState().inventory, null);
    runtime.controller.setSession('session-b', true);
    runtime.handlers.get('session_runtime_inventory')({
        success: true, session_id: 'session-a', request_id: 'runtime-inventory-1', systemd: { services: [] },
    });
    assert.equal(runtime.controller.getState().sessionId, 'session-b');
    assert.equal(runtime.controller.getState().inventory, null);
});

test('retains cached data as stale and reports first generic failure as unavailable', () => {
    const runtime = fakeRuntime();
    runtime.controller.setSession('session-a', true);
    runtime.controller.setOpen(true);
    runtime.handlers.get('session_runtime_inventory')({
        success: false, session_id: 'session-a', request_id: 'runtime-inventory-1',
    });
    assert.equal(runtime.renders.at(-1).status, 'unavailable');

    runtime.controller.refresh();
    runtime.handlers.get('session_runtime_inventory')({
        success: true, session_id: 'session-a', request_id: 'runtime-inventory-2', systemd: { services: [] },
    });
    runtime.controller.refresh();
    runtime.handlers.get('session_runtime_inventory')({
        success: false, session_id: 'session-a', request_id: 'runtime-inventory-3',
    });
    assert.equal(runtime.renders.at(-1).status, 'stale');
    assert.deepEqual(runtime.renders.at(-1).inventory, { systemd: { services: [] } });
});

test('scopes permission failures, isolates caches, removes one cache, and cleans up listeners', () => {
    const runtime = fakeRuntime();
    runtime.controller.setSession('session-a', true);
    runtime.controller.setOpen(true);
    runtime.handlers.get('session_runtime_inventory')({
        success: true, session_id: 'session-a', request_id: 'runtime-inventory-1',
        systemd: { services: [] }, docker: { containers: [] },
    });
    runtime.controller.refresh();
    runtime.handlers.get('session_runtime_inventory')({
        success: true, session_id: 'session-a', request_id: 'runtime-inventory-2',
        systemd: { services: [] },
        permission_denied: ['docker', 'unknown', 'docker'],
    });
    assert.deepEqual(runtime.renders.at(-1).inventory, { systemd: { services: [] } });
    assert.deepEqual(runtime.renders.at(-1).permissionDenied, ['docker']);

    runtime.controller.setSession('session-b', true);
    assert.equal(runtime.controller.getState().inventory, null);
    runtime.controller.setSession('session-a', true);
    assert.deepEqual(runtime.controller.getState().inventory, { systemd: { services: [] } });
    runtime.controller.removeSession('session-a');
    runtime.controller.setSession('session-a', true);
    assert.equal(runtime.controller.getState().inventory, null);
    runtime.controller.destroy();
    assert.equal(runtime.handlers.has('session_runtime_inventory'), false);
    assert.equal(runtime.timers.size, 0);
});
