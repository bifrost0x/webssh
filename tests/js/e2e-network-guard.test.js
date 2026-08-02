const test = require('node:test');
const assert = require('node:assert/strict');


function loadGuard(port) {
    const helperPath = require.resolve('../e2e/helpers');
    const previousPort = process.env.WEBSSH_E2E_PORT;
    process.env.WEBSSH_E2E_PORT = String(port);
    delete require.cache[helperPath];
    const helpers = require('../e2e/helpers');
    if (previousPort === undefined) {
        delete process.env.WEBSSH_E2E_PORT;
    } else {
        process.env.WEBSSH_E2E_PORT = previousPort;
    }
    delete require.cache[helperPath];
    return helpers;
}


function fakePage() {
    const listeners = {};
    return {
        on(event, handler) {
            listeners[event] = handler;
        },
        url() {
            return 'about:blank';
        },
        request(url) {
            listeners.request({ url: () => url });
        },
    };
}


test('E2E network guard allows the configured login origin before navigation', () => {
    const page = fakePage();
    const { installExternalRequestGuard } = loadGuard(4317);

    installExternalRequestGuard(page);
    page.request('http://127.0.0.1:4317/login');
    page.request('ws://127.0.0.1:4317/socket.io/?EIO=4');
    page.request('https://example.invalid/tracker.js');

    assert.deepEqual(page.__externalRequests, ['https://example.invalid/tracker.js']);
});
