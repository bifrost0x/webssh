const assert = require('node:assert/strict');
const test = require('node:test');

const filesPanel = require('../../static/js/session-files-panel.js');


function runtime() {
    const emitted = [];
    const handlers = new Map();
    const renders = [];
    const uploads = [];
    const downloads = [];
    const previews = [];
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
    const controller = filesPanel.createController({
        socket,
        render: state => renders.push(state),
        transferClient: {
            uploadFile(file, path, sessionId) {
                uploads.push({ file, path, sessionId });
            },
            downloadFile(path, sessionId) {
                downloads.push({ path, sessionId });
            },
        },
        filePreview: {
            open(sessionId, path, name) {
                previews.push({ sessionId, path, name });
            },
        },
    });
    return {
        controller, socket, emitted, handlers, renders,
        uploads, downloads, previews,
    };
}


test('normalizes remote paths without allowing relative traversal', () => {
    assert.equal(filesPanel.normalizePath('/srv/app/../logs'), '/srv/logs');
    assert.equal(filesPanel.joinPath('/srv/app', 'config.yml'), '/srv/app/config.yml');
    assert.equal(filesPanel.parentPath('/srv/app'), '/srv');
    assert.equal(filesPanel.parentPath('/'), '/');
});


test('opens on the active session home and follows a replacement session', () => {
    const state = runtime();
    state.controller.open('session-a', { username: 'ops', host: 'edge.example' });

    assert.deepEqual(state.emitted, [{
        event: 'get_home_directory',
        payload: { session_id: 'session-a' },
    }]);
    assert.equal(state.renders.at(-1).status, 'loading');
    assert.equal(state.renders.at(-1).label, 'ops@edge.example');

    state.handlers.get('home_directory')({
        session_id: 'session-a',
        path: '/home/ops',
    });
    assert.deepEqual(state.emitted.at(-1), {
        event: 'list_directory',
        payload: { session_id: 'session-a', remote_path: '/home/ops' },
    });

    state.controller.follow('session-b', { username: 'deploy', host: 'build.example' });
    assert.equal(state.renders.at(-1).sessionId, 'session-b');
    assert.equal(state.renders.at(-1).selectedIndex, -1);
    assert.deepEqual(state.emitted.at(-1), {
        event: 'get_home_directory',
        payload: { session_id: 'session-b' },
    });
});


test('ignores stale listings and renders only the current requested path', () => {
    const state = runtime();
    state.controller.open('session-a', { username: 'ops', host: 'edge.example' });
    state.handlers.get('home_directory')({ session_id: 'session-a', path: '/home/ops' });
    state.controller.follow('session-b', { username: 'deploy', host: 'build.example' });

    state.handlers.get('directory_listing')({
        session_id: 'session-a',
        path: '/home/ops',
        files: [{ name: 'secret', is_dir: false }],
    });
    assert.equal(state.renders.at(-1).sessionId, 'session-b');

    state.handlers.get('home_directory')({ session_id: 'session-b', path: '/srv/build' });
    state.controller.navigate('/srv/build/releases');
    state.handlers.get('directory_listing')({
        session_id: 'session-b',
        path: '/srv/build',
        files: [{ name: 'old', is_dir: false }],
    });
    assert.notEqual(state.renders.at(-1).files?.[0]?.name, 'old');

    state.handlers.get('directory_listing')({
        session_id: 'session-b',
        path: '/srv/build/releases',
        files: [{ name: 'v1', is_dir: true }],
    });
    assert.equal(state.renders.at(-1).files[0].name, 'v1');
});


test('opens folders inside the panel and files in the existing preview', () => {
    const state = runtime();
    state.controller.open('session-a', { username: 'ops', host: 'edge.example' });
    state.handlers.get('home_directory')({ session_id: 'session-a', path: '/home/ops' });
    state.handlers.get('directory_listing')({
        session_id: 'session-a',
        path: '/home/ops',
        files: [
            { name: 'logs', is_dir: true },
            { name: 'config.yml', is_dir: false, size: 100 },
        ],
    });

    state.controller.activate(0);
    assert.deepEqual(state.emitted.at(-1), {
        event: 'list_directory',
        payload: { session_id: 'session-a', remote_path: '/home/ops/logs' },
    });
    state.controller.navigate('/home/ops');
    state.handlers.get('directory_listing')({
        session_id: 'session-a',
        path: '/home/ops',
        files: [
            { name: 'logs', is_dir: true },
            { name: 'config.yml', is_dir: false, size: 100 },
        ],
    });
    state.controller.activate(1);
    assert.deepEqual(state.previews, [{
        sessionId: 'session-a',
        path: '/home/ops/config.yml',
        name: 'config.yml',
    }]);
});


test('delegates uploads and downloads to the existing transfer client', () => {
    const state = runtime();
    const file = { name: 'release.tgz', size: 42 };
    state.controller.open('session-a', { username: 'ops', host: 'edge.example' });
    state.handlers.get('home_directory')({ session_id: 'session-a', path: '/home/ops' });
    state.handlers.get('directory_listing')({
        session_id: 'session-a',
        path: '/home/ops',
        files: [{ name: 'report.txt', is_dir: false }],
    });

    state.controller.upload([file]);
    state.controller.select(0);
    state.controller.downloadSelected();

    assert.deepEqual(state.uploads, [{
        file,
        path: '/home/ops/release.tgz',
        sessionId: 'session-a',
    }]);
    assert.deepEqual(state.downloads, [{
        path: '/home/ops/report.txt',
        sessionId: 'session-a',
    }]);
});


test('uses existing mutation contracts and refreshes after completion', () => {
    const state = runtime();
    state.controller.open('session-a', { username: 'ops', host: 'edge.example' });
    state.handlers.get('home_directory')({ session_id: 'session-a', path: '/home/ops' });
    state.handlers.get('directory_listing')({
        session_id: 'session-a',
        path: '/home/ops',
        files: [{ name: 'old.txt', is_dir: false }],
    });
    state.controller.select(0);

    state.controller.createFolder('releases');
    state.controller.renameSelected('current.txt');
    state.controller.deleteSelected();

    assert.deepEqual(state.emitted.slice(-3), [
        {
            event: 'create_directory',
            payload: { session_id: 'session-a', remote_path: '/home/ops/releases' },
        },
        {
            event: 'rename_file',
            payload: {
                session_id: 'session-a',
                old_path: '/home/ops/old.txt',
                new_path: '/home/ops/current.txt',
            },
        },
        {
            event: 'delete_item',
            payload: { session_id: 'session-a', path: '/home/ops/old.txt' },
        },
    ]);

    state.handlers.get('directory_created')({ path: '/home/ops/releases' });
    assert.deepEqual(state.emitted.at(-1), {
        event: 'list_directory',
        payload: { session_id: 'session-a', remote_path: '/home/ops' },
    });
});


test('closes into an inert state and reports disconnects', () => {
    const state = runtime();
    state.controller.open('session-a', { username: 'ops', host: 'edge.example' });
    state.controller.setDisconnected('session-a');
    assert.equal(state.renders.at(-1).status, 'disconnected');

    state.controller.close();
    assert.equal(state.controller.isOpen(), false);
    const count = state.renders.length;
    state.handlers.get('directory_listing')({
        session_id: 'session-a', path: '/', files: [],
    });
    assert.equal(state.renders.length, count);
});
