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

function createElement(tagName = 'div') {
    const listeners = new Map();
    const classes = new Set();
    const element = {
        tagName: tagName.toUpperCase(),
        children: [],
        className: '',
        textContent: '',
        classList: {
            add(...names) {
                names.forEach(name => classes.add(name));
            },
            contains(name) {
                return classes.has(name);
            },
        },
        addEventListener(event, handler) {
            listeners.set(event, handler);
        },
        appendChild(child) {
            child.parentNode = element;
            element.children.push(child);
            return child;
        },
        click() {
            listeners.get('click')?.();
        },
        remove() {
            if (!element.parentNode) return;
            const siblings = element.parentNode.children;
            const index = siblings.indexOf(element);
            if (index !== -1) siblings.splice(index, 1);
            element.parentNode = null;
        },
        setAttribute() {},
    };
    return element;
}

function loadAppSocketHarness() {
    const handlers = new Map();
    const windowHandlers = new Map();
    const emitted = [];
    const notificationContainer = createElement('div');
    const state = { disconnects: 0, reloads: 0, unloads: [] };
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
        addEventListener(event, handler) {
            windowHandlers.set(event, [
                ...(windowHandlers.get(event) || []),
                handler,
            ]);
        },
        clearInterval() {},
        clearTimeout() {},
        console: { error() {}, log() {} },
        ConnectionLauncher: {
            createConnectionLauncher: () => ({ launch() {} }),
        },
        document: {
            addEventListener() {},
            createElement,
            getElementById(id) {
                return id === 'notificationContainer'
                    ? notificationContainer
                    : null;
            },
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
                const event = {
                    defaultPrevented: false,
                    preventDefault() {
                        event.defaultPrevented = true;
                    },
                };
                for (const handler of windowHandlers.get('beforeunload') || []) {
                    handler(event);
                }
                state.unloads.push({
                    prevented: event.defaultPrevented,
                    returnValue: event.returnValue,
                });
            },
        },
        SessionManager: { sessions: {} },
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
    return {
        browserGlobal,
        emitted,
        handlers,
        notificationContainer,
        state,
        windowHandlers,
    };
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

test('protocol reload bypasses the active-session unload warning exactly once', () => {
    const harness = loadAppSocketHarness();
    harness.browserGlobal.SessionManager.sessions = {
        active: { connected: true },
    };

    harness.handlers.get('connected')({
        status: 'success',
        username: 'old',
        wire_revision: SocketProtocol.WIRE_REVISION - 1,
    });

    assert.equal(harness.state.disconnects, 1);
    assert.equal(harness.state.reloads, 1);
    assert.equal(harness.state.unloads[0].prevented, false);
    assert.equal(harness.state.unloads[0].returnValue, undefined);
    const beforeUnload = harness.windowHandlers.get('beforeunload')?.at(-1);
    assert.equal(typeof beforeUnload, 'function');

    let normalPrevented = 0;
    const normalEvent = {
        preventDefault() { normalPrevented += 1; },
    };
    const warning = beforeUnload(normalEvent);
    assert.equal(normalPrevented, 1);
    assert.equal(normalEvent.returnValue, warning);
    assert.match(warning, /active SSH sessions/);

    const appSource = fs.readFileSync(
        path.join(ROOT, 'static', 'js', 'app.js'),
        'utf8',
    );
    assert.match(appSource, /reload: reloadForSocketProtocolMismatch/);
    assert.match(appSource, /onClick: reloadForSocketProtocolMismatch/);
});

test('cancelled dirty-editor reload keeps the protocol recovery action', () => {
    const harness = loadAppSocketHarness();
    harness.browserGlobal.SessionManager.sessions = {
        active: { connected: true },
    };
    harness.browserGlobal.addEventListener('beforeunload', (event) => {
        event.preventDefault();
        event.returnValue = '';
    });

    harness.handlers.get('connected')({
        status: 'success',
        username: 'old',
        wire_revision: SocketProtocol.WIRE_REVISION - 1,
    });

    assert.equal(harness.state.disconnects, 1);
    assert.equal(harness.state.reloads, 1);
    assert.equal(harness.state.unloads[0].prevented, true);
    assert.equal(harness.notificationContainer.children.length, 1);

    const notification = harness.notificationContainer.children[0];
    const action = notification.children.find(
        child => child.tagName === 'BUTTON',
    );
    assert.ok(action);

    action.click();

    assert.equal(harness.state.reloads, 2);
    assert.equal(harness.state.unloads[1].prevented, true);
    assert.equal(harness.notificationContainer.children.length, 1);
    assert.equal(notification.classList.contains('fade-out'), false);
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
        /function showSocketProtocolReloadNotice\(\)[\s\S]+persistent: true,[\s\S]+connection\.reloadPage/,
    );
    assert.match(
        appSource,
        /showManualReload: showSocketProtocolReloadNotice/,
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

test('unsaved notes warn before leaving even with no connected SSH session', () => {
    const harness = loadAppSocketHarness();
    harness.browserGlobal.notepadController = {hasUnsaved: () => true};
    const beforeUnload = harness.windowHandlers.get('beforeunload')?.at(-1);
    let prevented = false;
    const event = {preventDefault() {prevented = true;}};
    beforeUnload(event);
    assert.equal(prevented, true);
    assert.ok(event.returnValue);
});
