const test = require('node:test');
const assert = require('node:assert/strict');
const {runI18n} = require('./i18n-locales.js');

function loadI18n(localStorage, locales = ['en', 'de']) {
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
    runI18n({
        CustomEvent: class CustomEvent {},
        document,
        window,
    }, locales);
    return window;
}

test('unsupported stored languages fall back to English', () => {
    for (const stored of ['unsupported', '__proto__', 'constructor']) {
        const window = loadI18n({
            getItem() { return stored; },
            setItem() {},
        });

        assert.equal(window.i18n.getLanguage(), 'en', stored);
        assert.equal(window.i18n.t('common.actions'), 'Actions');
    }
});

test('blocked browser storage does not prevent translations from loading', async () => {
    const window = loadI18n({
        getItem() { throw new Error('storage denied'); },
        setItem() { throw new Error('storage denied'); },
    });

    assert.equal(window.i18n.getLanguage(), 'en');
    assert.equal(await window.i18n.setLanguage('de'), true);
    assert.equal(window.i18n.getLanguage(), 'de');
    assert.equal(window.i18n.t('common.actions'), 'Aktionen');
    assert.equal(window.BrowserPreferences.set('example', 'value'), false);
});
