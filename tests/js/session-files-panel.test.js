const assert = require('node:assert/strict');
const test = require('node:test');

const filesPanel = require('../../static/js/session-files-panel.js');


test('workspace adapter delegates embedded lifecycle to the shared file manager', () => {
    const calls = [];
    const manager = {
        openEmbedded(...args) { calls.push(['open', ...args]); },
        followEmbedded(...args) { calls.push(['follow', ...args]); },
        closeEmbedded() { calls.push(['close']); },
        handleEmbeddedDisconnect(id) { calls.push(['disconnect', id]); },
        isEmbeddedOpen() { return calls.at(-1)?.[0] !== 'close'; },
    };
    const container = { id: 'sessionFilesMount' };
    const controller = filesPanel.createController({ manager, container });
    const sessionA = { username: 'ops', host: 'edge.example' };
    const sessionB = { username: 'deploy', host: 'build.example' };

    controller.open('session-a', sessionA);
    controller.follow('session-b', sessionB);
    controller.setDisconnected('session-b');
    controller.close();

    assert.deepEqual(calls, [
        ['open', container, 'session-a', sessionA],
        ['follow', 'session-b', sessionB],
        ['disconnect', 'session-b'],
        ['close'],
    ]);
    assert.equal(controller.isOpen(), false);
});


test('workspace adapter requires the existing full file manager', () => {
    assert.throws(
        () => filesPanel.createController({ container: {} }),
        /SFTPFileManager/,
    );
    assert.throws(
        () => filesPanel.createController({ manager: {}, container: {} }),
        /openEmbedded/,
    );
});
