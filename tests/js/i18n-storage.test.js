const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync('static/js/i18n.js', 'utf8');

function loadI18n(localStorage) {
    const document = {
        documentElement: {},
        title: '',
        addEventListener() {},
        querySelector() { return null; },
        querySelectorAll() { return []; },
    };
    const window = {
        localStorage,
        dispatchEvent() {},
    };
    const context = vm.createContext({
        CustomEvent: class CustomEvent {},
        document,
        window,
    });
    vm.runInContext(source, context);
    return window;
}

test('unsupported stored languages fall back to English', () => {
    const window = loadI18n({
        getItem() { return 'unsupported'; },
        setItem() {},
    });

    assert.equal(window.i18n.getLanguage(), 'en');
    assert.equal(window.i18n.t('common.actions'), 'Actions');
});

test('blocked browser storage does not prevent translations from loading', () => {
    const window = loadI18n({
        getItem() { throw new Error('storage denied'); },
        setItem() { throw new Error('storage denied'); },
    });

    assert.equal(window.i18n.getLanguage(), 'en');
    assert.equal(window.i18n.setLanguage('de'), true);
    assert.equal(window.i18n.getLanguage(), 'de');
    assert.equal(window.i18n.t('common.actions'), 'Aktionen');
    assert.equal(window.BrowserPreferences.set('example', 'value'), false);
});
