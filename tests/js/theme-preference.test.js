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

test('the preferred background is available while the document is still loading', () => {
    const body = createBody({
        'data-theme': 'glass',
        'data-use-theme-preference': '',
        'data-defer-theme-background': '',
    });
    const window = {
        addEventListener() { throw new Error('background must not wait for load'); },
        requestIdleCallback() { throw new Error('background must not wait for idle'); },
        localStorage: { getItem() { return 'paper'; }, setItem() {} },
    };
    vm.runInContext(source, vm.createContext({document: {body, readyState: 'loading'}, window}));
    assert.equal(body.getAttribute('data-theme'), 'paper');
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

for (const stored of [null, 'not-a-theme', '<script>alert(1)</script>']) {
    test(`invalid or missing preference keeps the server theme (${stored})`, () => {
        const body = createBody({'data-theme': 'glass', 'data-use-theme-preference': '', 'data-defer-theme-background': ''});
        const window = {localStorage: {getItem() { return stored; }, setItem() {}}};
        vm.runInContext(source, vm.createContext({document: {body}, window}));
        assert.equal(body.getAttribute('data-theme'), 'glass');
        assert.equal(body.hasAttribute('data-theme-background-ready'), true);
    });
}

test('blocked browser storage does not prevent the background or preference API', () => {
    const body = createBody({'data-theme': 'glass', 'data-use-theme-preference': '', 'data-defer-theme-background': ''});
    const window = {get localStorage() { throw new Error('Storage blocked'); }};
    vm.runInContext(source, vm.createContext({document: {body}, window}));
    assert.equal(body.getAttribute('data-theme'), 'glass');
    assert.equal(body.hasAttribute('data-theme-background-ready'), true);
    assert.equal(window.ThemePreference.store('paper'), false);
    assert.equal(window.ThemePreference.read(), null);
});

test('server-selected password-change theme wins over a stored preference', () => {
    const body = createBody({'data-theme': 'retro', 'data-defer-theme-background': ''});
    const window = {localStorage: {getItem() { return 'paper'; }}};
    vm.runInContext(source, vm.createContext({document: {body}, window}));
    assert.equal(body.getAttribute('data-theme'), 'retro');
    assert.equal(body.hasAttribute('data-theme-background-ready'), true);
});

test('loading the helper without a body still exposes its validation API', () => {
    const window = {};
    vm.runInContext(source, vm.createContext({document: {body: null}, window}));
    assert.equal(window.ThemePreference.isValid('paper'), true);
    assert.equal(window.ThemePreference.isValid('invalid'), false);
});
