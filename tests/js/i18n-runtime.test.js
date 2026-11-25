const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const {localeSource, runtimeSource} = require('./i18n-locales.js');

const URLS = Object.fromEntries(['en', 'vi', 'de', 'fr', 'es', 'zh']
    .map(locale => [locale, `/static/js/i18n/${locale}.js?v=0123456789abcdef`]));

// A page that has parsed i18n.js (with its locale URL map) and is still loading.
function page({stored = null, urls = URLS, readyState = 'loading'} = {}) {
    const written = [];
    const appended = [];
    const events = [];
    const document = {
        readyState,
        title: '',
        documentElement: {},
        currentScript: {dataset: {locales: typeof urls === 'string' ? urls : JSON.stringify(urls)}},
        head: {appendChild(element) { appended.push(element); }},
        write(markup) { written.push(markup); },
        createElement(tag) {
            return {tag, remove() { this.removed = true; }};
        },
        addEventListener() {},
        querySelector() { return null; },
        querySelectorAll() { return []; },
    };
    const window = {
        localStorage: {getItem: () => stored, setItem(key, value) { this[key] = value; }},
        dispatchEvent(event) { events.push(event); },
    };
    const timers = [];
    const context = vm.createContext({
        window,
        document,
        URL,
        setTimeout(fn, delay) { timers.push({fn, delay}); return timers.length; },
        clearTimeout(id) { if (timers[id - 1]) timers[id - 1].cleared = true; },
        CustomEvent: class CustomEvent {
            constructor(name, options) { this.name = name; this.detail = options.detail; }
        },
    });
    vm.runInContext(runtimeSource, context);
    const register = locale => vm.runInContext(localeSource(locale), context);
    // Completes an asynchronous load the way the browser would: run the file, then fire onload.
    const finish = (element, locale) => { if (locale) register(locale); element.onload(); };
    return {window, document, written, appended, events, register, finish, timers};
}

test('startup inserts the stored non-English dictionary synchronously while the page parses', () => {
    const {window, written, register} = page({stored: 'de'});
    assert.deepEqual(written, [`<script src="${URLS.de}"></script>`]);
    register('en');
    register('de');
    assert.equal(window.i18n.getLanguage(), 'de');
    assert.equal(window.i18n.t('common.actions'), 'Aktionen');
});

test('English pages and already parsed documents never write markup', () => {
    assert.deepEqual(page({stored: 'en'}).written, []);
    assert.deepEqual(page({stored: null}).written, []);
    assert.deepEqual(page({stored: 'fr', readyState: 'interactive'}).written, []);
});

test('only well-formed same-origin asset paths are accepted as locale URLs', () => {
    for (const url of ['//evil.example/de.js?v=0123456789abcdef', 'https://evil.example/de.js?v=0123456789abcdef',
        '/static/js/i18n/de.js', '/static/js/i18n/de.js?v=0123456789abcdef"><script>', 'javascript:alert(1)',
        '/\\evil.example/de.js?v=0123456789abcdef', '/static/js/i18n/fr.js?v=0123456789abcdef',
        '/static/js/i18n/de.js?v=0123456789abcdef#x']) {
        assert.deepEqual(page({stored: 'de', urls: {...URLS, de: url}}).written, [], url);
    }
    assert.deepEqual(page({stored: 'de', urls: 'not json'}).written, []);
});

test('an application root with other valid path characters still loads its locale', () => {
    for (const [url, expected] of [
        ['/~ops/webssh/static/js/i18n/de.js?v=0123456789abcdef', '/~ops/webssh/static/js/i18n/de.js?v=0123456789abcdef'],
        ['/team@lab/static/js/i18n/de.js?v=0123456789abcdef', '/team@lab/static/js/i18n/de.js?v=0123456789abcdef'],
        ['/web%20ssh/static/js/i18n/de.js?v=0123456789abcdef', '/web%20ssh/static/js/i18n/de.js?v=0123456789abcdef'],
        ['/a"b/static/js/i18n/de.js?v=0123456789abcdef', '/a%22b/static/js/i18n/de.js?v=0123456789abcdef'],
    ]) {
        assert.deepEqual(page({stored: 'de', urls: {...URLS, de: url}}).written, [`<script src="${expected}"></script>`], url);
    }
});

test('missing dictionaries fall back to English and then to the key', () => {
    const {window, register} = page({stored: 'fr'});
    register('en');
    assert.equal(window.i18n.getLanguage(), 'fr');
    assert.equal(window.i18n.t('common.actions'), 'Actions');
    assert.equal(window.i18n.t('missing.key'), 'missing.key');
});

test('switching to a loaded language applies synchronously and dispatches languageChanged once', async () => {
    const {window, events, register} = page();
    register('en');
    register('de');
    const result = window.i18n.setLanguage('de');
    assert.equal(window.i18n.getLanguage(), 'de', 'applied before the promise settles');
    assert.equal(await result, true);
    assert.equal(window.localStorage.language, 'de');
    assert.deepEqual(events.map(event => [event.name, event.detail.lang]), [['languageChanged', 'de']]);
});

test('switching to an unloaded language loads its file first, then applies and dispatches', async () => {
    const {window, events, appended, register, finish} = page();
    register('en');
    const result = window.i18n.setLanguage('zh');
    assert.equal(window.i18n.getLanguage(), 'en');
    assert.equal(events.length, 0);
    assert.equal(appended.length, 1);
    assert.equal(appended[0].src, URLS.zh);
    const repeated = window.i18n.setLanguage('zh');
    assert.equal(appended.length, 1, 'concurrent requests share one load');
    finish(appended[0], 'zh');
    assert.equal(await result, true);
    assert.equal(await repeated, true);
    assert.equal(events.length, 1, 'a repeated request does not apply twice');
    assert.equal(window.i18n.getLanguage(), 'zh');
    assert.equal(window.i18n.t('common.actions'), '操作');
    assert.equal(events.at(-1).name, 'languageChanged');
    assert.equal(events.at(-1).detail.lang, 'zh');
    assert.equal(window.i18n.isLocaleLoaded('zh'), true);
});

test('only the most recent overlapping switch is applied', async () => {
    const {window, events, appended, register, finish} = page();
    register('en');
    const first = window.i18n.setLanguage('fr');
    const second = window.i18n.setLanguage('es');
    finish(appended[1], 'es');
    finish(appended[0], 'fr');
    assert.equal(await second, true);
    assert.equal(await first, false);
    assert.equal(window.i18n.getLanguage(), 'es');
    assert.deepEqual(events.map(event => event.detail.lang), ['es']);
});

test('a loaded language chosen while another is still loading wins', async () => {
    const {window, events, appended, register, finish} = page();
    register('en');
    const slow = window.i18n.setLanguage('vi');
    assert.equal(await window.i18n.setLanguage('en'), true);
    finish(appended[0], 'vi');
    assert.equal(await slow, false);
    assert.equal(window.i18n.getLanguage(), 'en');
    assert.deepEqual(events.map(event => event.detail.lang), ['en']);
});

test('a failed load keeps the current language and can be retried', async () => {
    const {window, events, appended, register, finish} = page();
    register('en');
    const failed = window.i18n.setLanguage('vi');
    appended[0].onerror();
    assert.equal(await failed, false);
    assert.equal(appended[0].removed, true);
    assert.equal(window.i18n.getLanguage(), 'en');
    assert.equal(events.length, 0);
    const retried = window.i18n.setLanguage('vi');
    assert.equal(appended.length, 2);
    finish(appended[1], 'vi');
    assert.equal(await retried, true);
    assert.equal(window.i18n.getLanguage(), 'vi');
});

test('a stalled load times out, removes its script and can be retried', async () => {
    const {window, events, appended, register, finish, timers} = page();
    register('en');
    const stalled = window.i18n.setLanguage('fr');
    assert.equal(timers.length, 1);
    assert.ok(timers[0].delay > 0 && timers[0].delay <= 30000);
    timers[0].fn();
    assert.equal(await stalled, false);
    assert.equal(appended[0].removed, true);
    assert.equal(appended[0].onload, null);
    assert.equal(window.i18n.getLanguage(), 'en');
    assert.equal(events.length, 0);
    const retried = window.i18n.setLanguage('fr');
    assert.equal(appended.length, 2);
    finish(appended[1], 'fr');
    assert.equal(await retried, true);
    assert.equal(timers[1].cleared, true);
});

test('a file that does not register its language is treated as a failure', async () => {
    const {window, appended, register, finish} = page();
    register('en');
    const result = window.i18n.setLanguage('de');
    finish(appended[0]);
    assert.equal(await result, false);
    assert.equal(window.i18n.getLanguage(), 'en');
});

test('unsupported languages are rejected without loading anything', async () => {
    const {window, appended} = page();
    assert.equal(await window.i18n.setLanguage('xx'), false);
    assert.equal(await window.i18n.setLanguage('__proto__'), false);
    assert.equal(appended.length, 0);
    await assert.rejects(window.i18n.loadLocale('xx'));
});

test('feature bundle entries survive a dictionary that registers later', async () => {
    const {window, appended, register, finish} = page();
    register('en');
    window.i18n.addTranslations('de', {'feature.only': 'Funktion', 'common.actions': 'Bundle wins'});
    const result = window.i18n.setLanguage('de');
    finish(appended[0], 'de');
    assert.equal(await result, true);
    assert.equal(window.i18n.t('feature.only'), 'Funktion');
    assert.equal(window.i18n.t('common.actions'), 'Bundle wins');
    assert.equal(window.i18n.t('common.cancel'), 'Abbrechen');
});
