const test = require('node:test');
const assert = require('node:assert/strict');

const { createCoordinator } = require('../../static/js/session-workspace.js');

function createHarness() {
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
        isDesktop: () => true,
        render: state => renders.push(state),
    });
    return { coordinator, calls, renders };
}

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
