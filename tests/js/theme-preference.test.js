const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync('static/js/theme-preference.js', 'utf8');

function createBody(attributes) {
    const values = new Map(Object.entries(attributes));
    return {
        getAttribute(name) { return values.get(name) ?? null; },
        hasAttribute(name) { return values.has(name); },
        setAttribute(name, value) { values.set(name, value); },
    };
}

test('a deferred theme background starts only after load and an idle turn', () => {
    const body = createBody({
        'data-theme': 'glass',
        'data-use-theme-preference': '',
        'data-defer-theme-background': '',
    });
    const listeners = new Map();
    let idleCallback;
    const window = {
        addEventListener(name, callback, options) {
            listeners.set(name, { callback, options });
        },
        localStorage: {
            getItem() { return 'paper'; },
            setItem() {},
        },
        requestIdleCallback(callback, options) {
            idleCallback = { callback, options };
        },
        setTimeout() { throw new Error('idle callback should be preferred'); },
    };
    const document = { body, readyState: 'loading' };

    vm.runInContext(source, vm.createContext({ document, window }));

    assert.equal(body.getAttribute('data-theme'), 'paper');
    assert.equal(body.hasAttribute('data-theme-background-ready'), false);
    assert.equal(listeners.get('load').options.once, true);

    listeners.get('load').callback();
    assert.equal(body.hasAttribute('data-theme-background-ready'), false);
    assert.equal(idleCallback.options.timeout, 1000);

    idleCallback.callback();
    assert.equal(body.hasAttribute('data-theme-background-ready'), true);
});

test('ordinary pages keep their theme background behavior unchanged', () => {
    const body = createBody({
        'data-theme': 'glass',
        'data-use-theme-preference': '',
    });
    let loadListenerAdded = false;
    const window = {
        addEventListener() { loadListenerAdded = true; },
        localStorage: {
            getItem() { return 'noir'; },
            setItem() {},
        },
    };

    vm.runInContext(
        source,
        vm.createContext({ document: { body, readyState: 'loading' }, window }),
    );

    assert.equal(body.getAttribute('data-theme'), 'noir');
    assert.equal(loadListenerAdded, false);
    assert.equal(body.hasAttribute('data-theme-background-ready'), false);
});

test('Rack Console is accepted by the browser preference guard', () => {
    const stored = [];
    const body = createBody({});
    const window = {
        addEventListener() {},
        localStorage: {
            getItem() { return null; },
            setItem(key, value) { stored.push([key, value]); },
        },
    };

    vm.runInContext(
        source,
        vm.createContext({ document: { body, readyState: 'loading' }, window }),
    );

    assert.equal(window.ThemePreference.isValid('rack-console'), true);
    assert.equal(window.ThemePreference.store('rack-console'), true);
    assert.deepEqual(stored, [['websshTheme', 'rack-console']]);
});
