const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const SocketProtocol = require('../../static/js/socket-protocol.js');
const ROOT = path.resolve(__dirname, '..', '..');

function createStorage() {
    const values = new Map();
    return {
        getItem(key) {
            return values.has(key) ? values.get(key) : null;
        },
        removeItem(key) {
            values.delete(key);
        },
        setItem(key, value) {
            values.set(key, String(value));
        },
    };
}

function loadAppSocketHarness() {
    const handlers = new Map();
    const emitted = [];
    const state = { disconnects: 0, reloads: 0 };
    const socket = {
        connected: true,
        disconnect() {
            state.disconnects += 1;
        },
        emit(event) {
            emitted.push(event);
        },
        io: { on() {} },
        on(event, handler) {
            handlers.set(event, handler);
        },
    };
    const browserGlobal = {
        addEventListener() {},
        clearInterval() {},
        clearTimeout() {},
        console: { error() {}, log() {} },
        ConnectionLauncher: {
            createConnectionLauncher: () => ({ launch() {} }),
        },
        document: {
            addEventListener() {},
            querySelector(selector) {
                return selector === 'meta[name="app-root"]'
                    ? { content: '' }
                    : null;
            },
        },
        io: () => socket,
        location: {
            reload() {
                state.reloads += 1;
            },
        },
        sessionStorage: createStorage(),
        setInterval: () => 1,
        setTimeout: () => 1,
        URL,
    };
    browserGlobal.window = browserGlobal;
    const context = vm.createContext(browserGlobal);
    for (const filename of [
        'socket-reconnect-policy.js',
        'socket-protocol.js',
        'app.js',
    ]) {
        vm.runInContext(
            fs.readFileSync(path.join(ROOT, 'static', 'js', filename), 'utf8'),
            context,
        );
    }
    return { emitted, handlers, state };
}

test('browser and server use the same hardcoded socket wire revision', () => {
    const pythonSource = fs.readFileSync(
        path.join(ROOT, 'app', 'socket_protocol.py'),
        'utf8',
    );
    const revision = pythonSource.match(/^SOCKET_WIRE_REVISION = (\d+)$/m);
    const event = pythonSource.match(
        /^SOCKET_PROTOCOL_MISMATCH_EVENT = '([^']+)'$/m,
    );

    assert.ok(revision);
    assert.equal(SocketProtocol.WIRE_REVISION, Number(revision[1]));
    assert.ok(event);
    assert.equal(SocketProtocol.MISMATCH_EVENT, event[1]);
});

test('server compatibility requires an exact successful revision', () => {
    assert.equal(SocketProtocol.isCompatibleServer({ status: 'success' }), false);
    assert.equal(SocketProtocol.isCompatibleServer({
        status: 'success',
        wire_revision: SocketProtocol.WIRE_REVISION - 1,
    }), false);
    assert.equal(SocketProtocol.isCompatibleServer({
        status: 'success',
        wire_revision: SocketProtocol.WIRE_REVISION,
    }), true);
});

test('app requests notepad only from a server with the exact revision', () => {
    for (const payload of [
        { status: 'success', username: 'legacy' },
        {
            status: 'success',
            username: 'old',
            wire_revision: SocketProtocol.WIRE_REVISION - 1,
        },
    ]) {
        const harness = loadAppSocketHarness();
        harness.handlers.get('connected')(payload);
        assert.equal(harness.state.disconnects, 1);
        assert.equal(harness.state.reloads, 1);
        assert.equal(harness.emitted.includes('get_notepad'), false);
    }

    const current = loadAppSocketHarness();
    current.handlers.get('connected')({
        status: 'success',
        username: 'current',
        wire_revision: SocketProtocol.WIRE_REVISION,
    });
    assert.equal(current.state.disconnects, 0);
    assert.equal(current.state.reloads, 0);
    assert.equal(current.emitted.filter(event => event === 'get_notepad').length, 1);
});

test('unrelated connection errors do not trigger a protocol reload', () => {
    const harness = loadAppSocketHarness();

    harness.handlers.get('connect_error')({
        data: { code: 'capacity_unavailable' },
    });

    assert.equal(harness.state.disconnects, 0);
    assert.equal(harness.state.reloads, 0);
});

test('authenticated page sends the revision and loads protocol before app', () => {
    const appSource = fs.readFileSync(
        path.join(ROOT, 'static', 'js', 'app.js'),
        'utf8',
    );
    const template = fs.readFileSync(
        path.join(ROOT, 'templates', 'index.html'),
        'utf8',
    );

    assert.ok(appSource.includes(
        'auth: { wire_revision: socketProtocol.WIRE_REVISION }',
    ));
    assert.ok(appSource.includes("socket.on('connect_error'"));
    assert.ok(appSource.includes(
        "error?.data?.code !== 'socket_protocol_mismatch'",
    ));
    assert.ok(
        template.indexOf("filename='js/socket-protocol.js'")
        < template.indexOf("filename='js/app.js'"),
    );
});

test('mismatch reloads once then requires a persistent manual reload', () => {
    const storage = createStorage();
    let disconnects = 0;
    let reloads = 0;
    let manualReloads = 0;
    const options = {
        storage,
        disconnect: () => { disconnects += 1; },
        reload: () => { reloads += 1; },
        showManualReload: () => { manualReloads += 1; },
    };
    const firstPage = SocketProtocol.createMismatchController(options);

    assert.equal(firstPage.handleMismatch({ required_revision: 2 }), 'reload');
    assert.equal(firstPage.handleMismatch({ required_revision: 2 }), 'ignored');
    assert.equal(reloads, 1);
    assert.equal(manualReloads, 0);

    const reloadedStalePage = SocketProtocol.createMismatchController(options);
    assert.equal(
        reloadedStalePage.handleMismatch({ required_revision: 2 }),
        'manual',
    );
    assert.equal(
        reloadedStalePage.handleMismatch({ required_revision: 2 }),
        'ignored',
    );
    assert.equal(disconnects, 2);
    assert.equal(reloads, 1);
    assert.equal(manualReloads, 1);

    const appSource = fs.readFileSync(
        path.join(ROOT, 'static', 'js', 'app.js'),
        'utf8',
    );
    assert.match(
        appSource,
        /showManualReload:[\s\S]+persistent: true,[\s\S]+connection\.reloadPage/,
    );
});

test('compatible backend does not re-arm reload during a rolling deployment', () => {
    const storage = createStorage();
    let reloads = 0;
    let manualReloads = 0;
    const options = {
        storage,
        reload: () => { reloads += 1; },
        showManualReload: () => { manualReloads += 1; },
    };
    const firstPage = SocketProtocol.createMismatchController(options);

    assert.equal(firstPage.handleMismatch({ required_revision: 2 }), 'reload');

    const reloadedPage = SocketProtocol.createMismatchController(options);
    reloadedPage.markCompatible();
    assert.equal(
        reloadedPage.handleMismatch({ required_revision: 2 }),
        'manual',
    );
    assert.equal(reloads, 1);
    assert.equal(manualReloads, 1);
});

test('restricted session storage degrades to the manual reload action', () => {
    let manualReloads = 0;
    const controller = SocketProtocol.createMismatchController({
        storage: {
            getItem() {
                throw new Error('storage denied');
            },
        },
        reload: () => assert.fail('automatic reload must remain guarded'),
        showManualReload: () => { manualReloads += 1; },
    });

    assert.equal(controller.handleMismatch({ required_revision: 2 }), 'manual');
    assert.equal(manualReloads, 1);
});
