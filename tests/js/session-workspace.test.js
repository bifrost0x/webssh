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

    assert.equal(coordinator.toggleSftp(), true);
    assert.deepEqual(calls.slice(-1), [['files.open', 's1', 'switch']]);
});

test('does not auto-open below the wide-desktop breakpoint but keeps manual SFTP available', () => {
    const { coordinator, calls } = createHarness({ isWideDesktop: () => false });
    coordinator.update({
        layout: 1,
        sessionId: 's1',
        session: { host: 'alpha', connected: true },
        sessionCount: 1,
    });

    assert.equal(coordinator.getState().sftpOpen, false);
    assert.equal(coordinator.toggleSftp(), true);
    assert.deepEqual(calls.slice(-1), [['files.open', 's1', 'alpha']]);
});

test('does not auto-open when more than one SSH session exists', () => {
    const { coordinator, calls } = createHarness({ isWideDesktop: () => true });
    coordinator.update({
        layout: 1,
        sessionId: 's1',
        session: { host: 'alpha', connected: true },
        sessionCount: 2,
    });

    assert.equal(coordinator.getState().sftpOpen, false);
    assert.equal(calls.some(call => call[0] === 'files.open'), false);
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

test('opens embedded SFTP only for a connected session in layout 1', () => {
    const { coordinator, calls } = createHarness();
    coordinator.update({ layout: 1, sessionId: 's1', session: { host: 'alpha', connected: true } });

    assert.equal(coordinator.toggleSftp(), true);
    assert.deepEqual(calls.slice(-1), [['files.open', 's1', 'alpha']]);
    assert.equal(coordinator.getState().sftpOpen, true);
});

test('refuses SFTP without a connected session or on a narrow viewport', () => {
    const { coordinator } = createHarness();
    coordinator.update({ layout: 1, sessionId: null, session: null });
    assert.equal(coordinator.toggleSftp(), false);

    const filesPanel = { open() { throw new Error('must not open'); }, close() {} };
    const narrow = createCoordinator({ filesPanel, insights: {}, isDesktop: () => false });
    narrow.update({ layout: 1, sessionId: 's1', session: { connected: true } });
    assert.equal(narrow.toggleSftp(), false);
});

test('follows the active session while SFTP is open and always retargets insights', () => {
    const { coordinator, calls } = createHarness();
    coordinator.update({ layout: 1, sessionId: 's1', session: { host: 'alpha', connected: true } });
    coordinator.toggleSftp();
    calls.length = 0;

    coordinator.update({ layout: 1, sessionId: 's2', session: { host: 'beta', connected: true } });

    assert.deepEqual(calls, [
        ['insights.session', 's2', true],
        ['files.follow', 's2', 'beta'],
    ]);
});

test('switching to 2 or 4 closes SFTP and returning to 1 keeps it closed', () => {
    const { coordinator, calls } = createHarness();
    coordinator.update({ layout: 1, sessionId: 's1', session: { host: 'alpha', connected: true } });
    coordinator.toggleSftp();
    calls.length = 0;

    coordinator.update({ layout: 2, sessionId: 's1', session: { host: 'alpha', connected: true } });
    coordinator.update({ layout: 1, sessionId: 's1', session: { host: 'alpha', connected: true } });

    assert.deepEqual(calls.filter(call => call[0].startsWith('files.')), [['files.close']]);
    assert.equal(coordinator.getState().sftpOpen, false);
});

test('disconnect closes SFTP and marks insights disconnected', () => {
    const { coordinator, calls } = createHarness();
    coordinator.update({ layout: 1, sessionId: 's1', session: { host: 'alpha', connected: true } });
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

test('visibility pauses and resumes live insights without changing SFTP state', () => {
    const { coordinator, calls } = createHarness();
    coordinator.update({ layout: 1, sessionId: 's1', session: { host: 'alpha', connected: true } });
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

    handlers.session_sftp_capability({
        success: true,
        available: true,
        session_id: 's1',
        request_id: 'stale-probe',
    });
    assert.equal(tracker.get('s1'), 'unknown');

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

    assert.equal(tracker.get('s1'), 'unknown');
    assert.equal(timers.size, 1);
    assert.equal([...timers.values()][0].delay, 10000);
    [...timers.values()][0].callback();
    assert.deepEqual(emitted.at(-1), ['probe_session_sftp', {
        session_id: 's1',
        request_id: 'probe-2',
    }]);
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

    assert.equal(tracker.get('s1'), 'unknown');
    const retry = [...timers.values()].find(timer => timer.delay === 10000);
    retry.callback();
    assert.equal(emitted.at(-1)[1].request_id, 'probe-2');
});
