const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function loadBrowserErrorHandler(errors) {
    const handlers = new Map();
    const socket = {
        connected: false,
        emit() {},
        on() {},
        io: { on() {} },
    };
    const browserGlobal = {
        addEventListener(type, handler) {
            handlers.set(type, handler);
        },
        document: {
            addEventListener() {},
            querySelector(selector) {
                return selector === 'meta[name="app-root"]' ? { content: '' } : null;
            },
        },
        io: () => socket,
        ConnectionLauncher: {
            createConnectionLauncher: () => ({ launch() {} }),
        },
        console: {
            error: (...args) => errors.push(args),
            log() {},
        },
        setInterval: () => 1,
        clearInterval() {},
        setTimeout: () => 1,
        clearTimeout() {},
        URL,
    };
    browserGlobal.window = browserGlobal;

    const context = vm.createContext(browserGlobal);

    vm.runInContext(
        fs.readFileSync('static/js/socket-reconnect-policy.js', 'utf8'),
        context
    );
    vm.runInContext(fs.readFileSync('static/js/app.js', 'utf8'), context);
    return handlers.get('error');
}

test('reports browser errors whose source URL merely contains socket.io', () => {
    const errors = [];
    const handleError = loadBrowserErrorHandler(errors);

    handleError({
        filename: 'https://attacker.example/assets/app.js?source=socket.io',
    });

    assert.deepEqual(errors, [['[WebSSH] Uncaught browser error']]);
});
