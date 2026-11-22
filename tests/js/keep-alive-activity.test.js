const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function setup({connected = true} = {}) {
    const listeners = {};
    const emitted = [];
    const context = {
        document: {
            visibilityState: 'visible',
            addEventListener(type, handler, options) {
                assert.equal(options.capture, true);
                listeners[type] = handler;
            },
        },
        socket: {connected, emit: (...args) => emitted.push(args)},
        setInterval: () => 1,
    };
    const source = fs.readFileSync(path.join(__dirname, '../../static/js/app.js'), 'utf8');
    const start = source.indexOf('    let userActiveSinceKeepAlive = false;');
    const end = source.indexOf('    let keepAliveInterval = setInterval(sendKeepAlive', start);
    assert.ok(start > 0 && end > start);
    vm.runInNewContext(source.slice(start, end) + '\nglobalThis.sendKeepAlive = sendKeepAlive;', context);
    return {context, listeners, emitted};
}

test('keep_alive reports activity only after input in a visible tab', () => {
    const {context, listeners, emitted} = setup();
    context.sendKeepAlive();
    listeners.keydown();
    context.sendKeepAlive();
    context.sendKeepAlive();
    assert.deepEqual(emitted.map(([name, payload]) => [name, payload.active]), [
        ['keep_alive', false],
        ['keep_alive', true],
        ['keep_alive', false],
    ]);
});

test('pointer, wheel and touch input count as activity', () => {
    const {listeners} = setup();
    assert.deepEqual(Object.keys(listeners).sort(),
        ['keydown', 'pointerdown', 'pointermove', 'touchstart', 'wheel']);
});

test('input in a hidden tab does not count as activity', () => {
    const {context, listeners, emitted} = setup();
    listeners.pointerdown();
    context.document.visibilityState = 'hidden';
    context.sendKeepAlive();
    assert.equal(emitted[0][1].active, false);
});

test('no keep_alive is sent while the socket is disconnected', () => {
    const {context, emitted} = setup({connected: false});
    context.sendKeepAlive();
    assert.deepEqual(emitted, []);
});
