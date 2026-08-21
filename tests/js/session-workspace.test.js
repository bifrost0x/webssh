const test = require('node:test');
const assert = require('node:assert/strict');

const {
    createCoordinator,
    createSftpCapabilityTracker,
} = require('../../static/js/session-workspace.js');

function createHarness(options = {}) {
    const calls = [];
    const filesPanel = {
        open(id, session) { calls.push(['files.open', id, session.host]); },
        follow(id, session) { calls.push(['files.follow', id, session.host]); },
        close() { calls.push(['files.close']); },
        setDisconnected(id) { calls.push(['files.disconnected', id]); },
    };
    const insights = {
        setSession(id, connected) { calls.push(['insights.session', id, connected]); },
        setVisible(visible) { calls.push(['insights.visible', visible]); },
    };
    const renders = [];
    const coordinator = createCoordinator({
        filesPanel,
        insights,
        isDesktop: options.isDesktop || (() => true),
        isWideDesktop: options.isWideDesktop || (() => false),
        render: state => renders.push(state),
    });
    return { coordinator, calls, renders };
}

test('auto-opens embedded SFTP for the sole connected session on a wide desktop', () => {
    const { coordinator, calls } = createHarness({ isWideDesktop: () => true });

    coordinator.update({
        layout: 1,
        sessionId: 's1',
        session: { host: 'alpha', connected: true },
        sessionCount: 1,
        sftpCapability: 'available',
    });

    assert.deepEqual(calls.slice(-2), [
        ['insights.session', 's1', true],
        ['files.open', 's1', 'alpha'],
    ]);
    assert.equal(coordinator.getState().sftpOpen, true);
});

test('keeps an auto-opened SFTP panel open below the wide breakpoint', () => {
    let wideDesktop = true;
    const { coordinator, calls } = createHarness({
        isWideDesktop: () => wideDesktop,
    });
    const update = {
        layout: 1,
        sessionId: 's1',
        session: { host: 'alpha', connected: true },
        sessionCount: 1,
        sftpCapability: 'available',
    };
    coordinator.update(update);
    calls.length = 0;

    wideDesktop = false;
    coordinator.update(update);

    assert.equal(coordinator.getState().sftpOpen, true);
    assert.deepEqual(calls, []);
});

test('probes before auto-opening embedded SFTP and stays closed when unavailable', () => {
    const { coordinator, calls } = createHarness({ isWideDesktop: () => true });
    const update = sftpCapability => coordinator.update({
        layout: 1,
        sessionId: 's1',
        session: { host: 'switch', connected: true },
        sessionCount: 1,
        sftpCapability,
    });

    update('unknown');
    assert.equal(coordinator.getState().sftpOpen, false);
    assert.equal(coordinator.getState().sftpProbeNeeded, true);
    assert.equal(calls.some(call => call[0] === 'files.open'), false);

    update('unavailable');
    assert.equal(coordinator.getState().sftpOpen, false);
    assert.equal(coordinator.getState().sftpProbeNeeded, false);
    assert.equal(calls.some(call => call[0] === 'files.open'), false);

    assert.equal(coordinator.toggleSftp(), false);
    assert.equal(calls.some(call => call[0] === 'files.open'), false);
});

test('probes below the wide-desktop breakpoint and keeps capable SFTP manually available', () => {
    const { coordinator, calls } = createHarness({ isWideDesktop: () => false });
    coordinator.update({
        layout: 1,
        sessionId: 's1',
        session: { host: 'alpha', connected: true },
        sessionCount: 1,
        sftpCapability: 'unknown',
    });

    assert.equal(coordinator.getState().sftpOpen, false);
    assert.equal(coordinator.getState().sftpProbeNeeded, true);
    assert.equal(coordinator.toggleSftp(), false);

    coordinator.update({
        layout: 1,
        sessionId: 's1',
        session: { host: 'alpha', connected: true },
        sessionCount: 1,
        sftpCapability: 'available',
    });
    assert.equal(coordinator.toggleSftp(), true);
    assert.deepEqual(calls.slice(-1), [['files.open', 's1', 'alpha']]);
});

test('auto-opens a capable active session even when other SSH sessions exist', () => {
    const { coordinator, calls } = createHarness({ isWideDesktop: () => true });
    coordinator.update({
        layout: 1,
        sessionId: 's1',
        session: { host: 'alpha', connected: true },
        sessionCount: 2,
        sftpCapability: 'available',
    });

    assert.equal(coordinator.getState().sftpOpen, true);
    assert.deepEqual(calls.slice(-1), [['files.open', 's1', 'alpha']]);
});

test('manual close suppresses automatic reopening for the same session', () => {
    const { coordinator, calls } = createHarness({ isWideDesktop: () => true });
    const update = {
        layout: 1,
        sessionId: 's1',
        session: { host: 'alpha', connected: true },
        sessionCount: 1,
        sftpCapability: 'available',
    };
    coordinator.update(update);
    assert.equal(coordinator.toggleSftp(), false);
    calls.length = 0;

    coordinator.update(update);

    assert.equal(coordinator.getState().sftpOpen, false);
    assert.deepEqual(calls, []);
});

test('removing a session clears its SFTP visibility preference', () => {
    const { coordinator } = createHarness({ isWideDesktop: () => true });
    const update = {
        layout: 1,
        sessionId: 's1',
        session: { host: 'alpha', connected: true },
        sessionCount: 1,
        sftpCapability: 'available',
    };
    coordinator.update(update);
    assert.equal(coordinator.toggleSftp(), false);

    coordinator.removeSession('s1');
    coordinator.update(update);

    assert.equal(coordinator.getState().sftpOpen, true);
});

test('closes SFTP for an unavailable session and restores it for the capable session', () => {
    const { coordinator, calls } = createHarness({ isWideDesktop: () => true });
    coordinator.update({
        layout: 1,
        sessionId: 'linux',
        session: { host: 'server', connected: true },
        sessionCount: 1,
        sftpCapability: 'available',
    });
    calls.length = 0;

    coordinator.update({
        layout: 1,
        sessionId: 'cisco',
        session: { host: 'switch', connected: true },
        sessionCount: 2,
        sftpCapability: 'unavailable',
    });

    assert.equal(coordinator.getState().sftpOpen, false);
    assert.deepEqual(calls, [
        ['insights.session', 'cisco', true],
        ['files.close'],
    ]);

    calls.length = 0;
    coordinator.update({
        layout: 1,
        sessionId: 'linux',
        session: { host: 'server', connected: true },
        sessionCount: 2,
        sftpCapability: 'available',
    });

    assert.equal(coordinator.getState().sftpOpen, true);
    assert.deepEqual(calls, [
        ['insights.session', 'linux', true],
        ['files.open', 'linux', 'server'],
    ]);
});

test('probes the active session even when other SSH sessions exist', () => {
    const { coordinator } = createHarness({ isWideDesktop: () => true });

    coordinator.update({
        layout: 1,
        sessionId: 'cisco',
        session: { host: 'switch', connected: true },
        sessionCount: 2,
        sftpCapability: 'unknown',
    });

    assert.equal(coordinator.getState().sftpProbeNeeded, true);
    assert.equal(coordinator.getState().sftpOpen, false);
});

test('keeps manual SFTP visibility preferences isolated per session', () => {
    const { coordinator, calls } = createHarness();
    coordinator.update({
        layout: 1,
        sessionId: 'linux',
        session: { host: 'server', connected: true },
        sessionCount: 2,
        sftpCapability: 'available',
    });
    assert.equal(coordinator.toggleSftp(), true);
    calls.length = 0;

    coordinator.update({
        layout: 1,
        sessionId: 'cisco',
        session: { host: 'switch', connected: true },
        sessionCount: 2,
        sftpCapability: 'unavailable',
    });

    assert.equal(coordinator.getState().sftpOpen, false);
    assert.equal(coordinator.toggleSftp(), false);
    assert.deepEqual(calls, [
        ['insights.session', 'cisco', true],
        ['files.close'],
    ]);

    calls.length = 0;
    coordinator.update({
        layout: 1,
        sessionId: 'linux',
        session: { host: 'server', connected: true },
        sessionCount: 2,
        sftpCapability: 'available',
    });

    assert.equal(coordinator.getState().sftpOpen, true);
    assert.deepEqual(calls, [
        ['insights.session', 'linux', true],
        ['files.open', 'linux', 'server'],
    ]);
});

test('opens embedded SFTP only for a connected session in layout 1', () => {
    const { coordinator, calls } = createHarness();
    coordinator.update({
        layout: 1,
        sessionId: 's1',
        session: { host: 'alpha', connected: true },
        sftpCapability: 'available',
    });

    assert.equal(coordinator.toggleSftp(), true);
    assert.deepEqual(calls.slice(-1), [['files.open', 's1', 'alpha']]);
    assert.equal(coordinator.getState().sftpOpen, true);
});

test('refuses SFTP without a connected session but keeps Files usable on narrow viewports', () => {
    const { coordinator } = createHarness();
    coordinator.update({ layout: 1, sessionId: null, session: null });
    assert.equal(coordinator.toggleSftp(), false);

    let openedSessionId = null;
    const filesPanel = { open(id) { openedSessionId = id; }, close() {} };
    const narrow = createCoordinator({ filesPanel, insights: {}, isDesktop: () => false });
    narrow.update({
        layout: 1,
        sessionId: 's1',
        session: { connected: true },
        sftpCapability: 'available',
    });
    assert.equal(narrow.toggleSftp(), true);
    assert.equal(openedSessionId, 's1');
});

test('opening the Files context is idempotent and tab changes do not close SFTP', () => {
    const { coordinator, calls } = createHarness();
    coordinator.update({
        layout: 1,
        sessionId: 's1',
        session: { host: 'alpha', connected: true },
        sftpCapability: 'available',
    });

    assert.equal(coordinator.openSftpPanel(), true);
    assert.equal(coordinator.openSftpPanel(), true);
    assert.deepEqual(
        calls.filter(call => call[0] === 'files.open'),
        [['files.open', 's1', 'alpha']],
    );
    assert.equal(coordinator.getState().sftpOpen, true);
});

test('follows the active session only when the new session is capable and open', () => {
    const { coordinator, calls } = createHarness({ isWideDesktop: () => true });
    coordinator.update({
        layout: 1,
        sessionId: 's1',
        session: { host: 'alpha', connected: true },
        sessionCount: 1,
        sftpCapability: 'available',
    });
    calls.length = 0;

    coordinator.update({
        layout: 1,
        sessionId: 's2',
        session: { host: 'beta', connected: true },
        sessionCount: 2,
        sftpCapability: 'available',
    });

    assert.deepEqual(calls, [
        ['insights.session', 's2', true],
        ['files.follow', 's2', 'beta'],
    ]);
});

test('switching to 2 or 4 closes SFTP and returning to 1 keeps it closed', () => {
    const { coordinator, calls } = createHarness();
    coordinator.update({
        layout: 1,
        sessionId: 's1',
        session: { host: 'alpha', connected: true },
        sftpCapability: 'available',
    });
    coordinator.toggleSftp();
    calls.length = 0;

    coordinator.update({ layout: 2, sessionId: 's1', session: { host: 'alpha', connected: true } });
    coordinator.update({ layout: 1, sessionId: 's1', session: { host: 'alpha', connected: true } });

    assert.deepEqual(calls.filter(call => call[0].startsWith('files.')), [['files.close']]);
    assert.equal(coordinator.getState().sftpOpen, false);
});

test('disconnect closes SFTP and marks insights disconnected', () => {
    const { coordinator, calls } = createHarness();
    coordinator.update({
        layout: 1,
        sessionId: 's1',
        session: { host: 'alpha', connected: true },
        sftpCapability: 'available',
    });
    coordinator.toggleSftp();
    calls.length = 0;

    coordinator.update({ layout: 1, sessionId: 's1', session: { host: 'alpha', connected: false } });

    assert.deepEqual(calls, [
        ['insights.session', 's1', false],
        ['files.disconnected', 's1'],
        ['files.close'],
    ]);
    assert.equal(coordinator.getState().sftpOpen, false);
});

test('restores an explicit SFTP preference after a transient disconnect', () => {
    const { coordinator, calls } = createHarness();
    const update = connected => coordinator.update({
        layout: 1,
        sessionId: 's1',
        session: { host: 'alpha', connected },
        sftpCapability: 'available',
    });
    update(true);
    coordinator.toggleSftp();
    calls.length = 0;

    update(false);
    update(true);

    assert.equal(coordinator.getState().sftpOpen, true);
    assert.deepEqual(calls.filter(call => call[0].startsWith('files.')), [
        ['files.disconnected', 's1'],
        ['files.close'],
        ['files.open', 's1', 'alpha'],
    ]);
});

test('visibility pauses and resumes live insights without changing SFTP state', () => {
    const { coordinator, calls } = createHarness();
    coordinator.update({
        layout: 1,
        sessionId: 's1',
        session: { host: 'alpha', connected: true },
        sftpCapability: 'available',
    });
    coordinator.toggleSftp();
    calls.length = 0;

    coordinator.setVisible(false);
    coordinator.setVisible(true);

    assert.deepEqual(calls, [
        ['insights.visible', false],
        ['insights.visible', true],
    ]);
    assert.equal(coordinator.getState().sftpOpen, true);
});

test('SFTP capability tracker probes once and accepts only its correlated response', () => {
    const handlers = {};
    const emitted = [];
    const changes = [];
    const socket = {
        on(event, handler) { handlers[event] = handler; },
        emit(event, payload) { emitted.push([event, payload]); },
    };
    const tracker = createSftpCapabilityTracker({
        socket,
        onChange(sessionId) { changes.push(sessionId); },
        createRequestId: () => 'probe-1',
    });
    const candidate = { sessionId: 's1', sftpProbeNeeded: true };

    tracker.probeIfNeeded(candidate);
    tracker.probeIfNeeded(candidate);
    assert.deepEqual(emitted, [['probe_session_sftp', {
        session_id: 's1',
        request_id: 'probe-1',
    }]]);
    assert.equal(tracker.get('s1'), 'probing');

    handlers.session_sftp_capability({
        success: true,
        available: true,
        session_id: 's1',
        request_id: 'stale-probe',
    });
    assert.equal(tracker.get('s1'), 'probing');

    handlers.session_sftp_capability({
        success: true,
        available: true,
        session_id: 's1',
        request_id: 'probe-1',
    });
    assert.equal(tracker.get('s1'), 'available');
    assert.deepEqual(changes, ['s1']);

    tracker.remove('s1');
    assert.equal(tracker.get('s1'), 'unknown');
});

test('SFTP capability tracker retries a busy probe without opening the pane', () => {
    const handlers = {};
    const emitted = [];
    const timers = new Map();
    let nextTimer = 1;
    let nextRequest = 1;
    const socket = {
        on(event, handler) { handlers[event] = handler; },
        emit(event, payload) { emitted.push([event, payload]); },
    };
    const tracker = createSftpCapabilityTracker({
        socket,
        createRequestId: () => `probe-${nextRequest++}`,
        setTimeoutFn(callback, delay) {
            const id = nextTimer++;
            timers.set(id, { callback, delay });
            return id;
        },
        clearTimeoutFn(id) { timers.delete(id); },
    });
    const candidate = { sessionId: 's1', sftpProbeNeeded: true };

    tracker.probeIfNeeded(candidate);
    handlers.session_sftp_capability({
        success: false,
        available: false,
        session_id: 's1',
        request_id: 'probe-1',
    });

    assert.equal(tracker.get('s1'), 'probing');
    assert.equal(timers.size, 1);
    assert.equal([...timers.values()][0].delay, 10000);
    tracker.probeIfNeeded({
        sessionId: 's1',
        sftpProbeNeeded: true,
        sftpCapability: 'probing',
    });
    assert.equal(timers.size, 1);
    assert.equal(tracker.get('s1'), 'probing');
    [...timers.values()][0].callback();
    assert.deepEqual(emitted.at(-1), ['probe_session_sftp', {
        session_id: 's1',
        request_id: 'probe-2',
    }]);
});

test('SFTP capability tracker cancels retries while the session is ineligible', () => {
    const handlers = {};
    const emitted = [];
    const timers = new Map();
    let nextTimer = 1;
    let nextRequest = 1;
    const tracker = createSftpCapabilityTracker({
        socket: {
            on(event, handler) { handlers[event] = handler; },
            emit(event, payload) { emitted.push([event, payload]); },
        },
        createRequestId: () => `probe-${nextRequest++}`,
        setTimeoutFn(callback, delay) {
            const id = nextTimer++;
            timers.set(id, { callback, delay });
            return id;
        },
        clearTimeoutFn(id) { timers.delete(id); },
    });

    tracker.probeIfNeeded({ sessionId: 's1', sftpProbeNeeded: true });
    handlers.session_sftp_capability({
        success: false,
        available: false,
        session_id: 's1',
        request_id: 'probe-1',
    });
    assert.equal([...timers.values()].some(timer => timer.delay === 10000), true);

    tracker.probeIfNeeded({
        sessionId: 's1',
        sftpProbeNeeded: false,
        sftpCapability: 'probing',
    });

    assert.equal(timers.size, 0);
    assert.equal(tracker.get('s1'), 'unknown');
    assert.equal(emitted.length, 1);
});

test('SFTP capability tracker cancels an in-flight probe during disconnect', () => {
    const handlers = {};
    const emitted = [];
    const timers = new Map();
    let nextTimer = 1;
    const tracker = createSftpCapabilityTracker({
        socket: {
            on(event, handler) { handlers[event] = handler; },
            emit(event, payload) { emitted.push([event, payload]); },
        },
        createRequestId: () => 'probe-1',
        setTimeoutFn(callback, delay) {
            const id = nextTimer++;
            timers.set(id, { callback, delay });
            return id;
        },
        clearTimeoutFn(id) { timers.delete(id); },
    });

    tracker.probeIfNeeded({ sessionId: 's1', sftpProbeNeeded: true });
    tracker.probeIfNeeded({
        sessionId: 's1',
        sftpProbeNeeded: false,
        sftpCapability: 'probing',
    });
    handlers.session_sftp_capability({
        success: false,
        available: false,
        session_id: 's1',
        request_id: 'probe-1',
    });

    assert.equal(timers.size, 0);
    assert.equal(tracker.get('s1'), 'unknown');
    assert.equal(emitted.length, 1);
});

test('SFTP capability tracker expires a lost request and ignores its late response', () => {
    const handlers = {};
    const emitted = [];
    const timers = new Map();
    let nextTimer = 1;
    let nextRequest = 1;
    const tracker = createSftpCapabilityTracker({
        socket: {
            on(event, handler) { handlers[event] = handler; },
            emit(event, payload) { emitted.push([event, payload]); },
        },
        createRequestId: () => `probe-${nextRequest++}`,
        setTimeoutFn(callback, delay) {
            const id = nextTimer++;
            timers.set(id, { callback, delay });
            return id;
        },
        clearTimeoutFn(id) { timers.delete(id); },
    });

    tracker.probeIfNeeded({ sessionId: 's1', sftpProbeNeeded: true });
    const [deadlineId, deadline] = [...timers.entries()]
        .find(([_id, timer]) => timer.delay === 5000);
    timers.delete(deadlineId);
    deadline.callback();
    handlers.session_sftp_capability({
        success: true,
        available: true,
        session_id: 's1',
        request_id: 'probe-1',
    });

    assert.equal(tracker.get('s1'), 'probing');
    const retry = [...timers.values()].find(timer => timer.delay === 10000);
    retry.callback();
    assert.equal(emitted.at(-1)[1].request_id, 'probe-2');
});

test('SFTP capability tracker records an authoritative unavailable result', () => {
    const handlers = {};
    const tracker = createSftpCapabilityTracker({
        socket: {
            on(event, handler) { handlers[event] = handler; },
            emit() {},
        },
        createRequestId: () => 'probe-1',
    });

    tracker.probeIfNeeded({ sessionId: 'switch', sftpProbeNeeded: true });
    handlers.session_sftp_capability({
        success: true,
        available: false,
        session_id: 'switch',
        request_id: 'probe-1',
    });

    assert.equal(tracker.get('switch'), 'unavailable');
});

test('SFTP capability tracker exposes manual fallback after bounded probe failures', () => {
    const handlers = {};
    const timers = new Map();
    let nextTimer = 1;
    let nextRequest = 1;
    const tracker = createSftpCapabilityTracker({
        socket: {
            on(event, handler) { handlers[event] = handler; },
            emit() {},
        },
        createRequestId: () => `probe-${nextRequest++}`,
        setTimeoutFn(callback, delay) {
            const id = nextTimer++;
            timers.set(id, { callback, delay });
            return id;
        },
        clearTimeoutFn(id) { timers.delete(id); },
    });

    tracker.probeIfNeeded({ sessionId: 'appliance', sftpProbeNeeded: true });
    for (let attempt = 1; attempt <= 3; attempt += 1) {
        handlers.session_sftp_capability({
            success: false,
            available: false,
            session_id: 'appliance',
            request_id: `probe-${attempt}`,
        });
        const retry = [...timers.entries()]
            .find(([_id, timer]) => timer.delay === 10000);
        if (retry) {
            timers.delete(retry[0]);
            retry[1].callback();
        }
    }

    assert.equal(tracker.get('appliance'), 'inconclusive');
    assert.equal([...timers.values()].some(timer => timer.delay === 10000), false);
});
