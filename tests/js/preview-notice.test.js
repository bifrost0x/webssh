const assert = require('node:assert/strict');
const test = require('node:test');
const notice = require('../../static/js/preview-notice.js');

function fakeDocument() {
    const element = tag => {
        const node = {
            tagName: tag.toUpperCase(), children: [], attributes: {}, listeners: {}, hidden: false, textContent: '',
            append(...nodes) { this.children.push(...nodes); },
            prepend(...nodes) { this.children.unshift(...nodes); },
            setAttribute(name, value) { this.attributes[name] = String(value); },
            addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); },
            click() { (this.listeners.click || []).forEach(fn => fn({})); },
        };
        return node;
    };
    return {body: element('body'), createElement: element, addEventListener() {}};
}

function setup({storage = new Map(), i18n} = {}) {
    const document = fakeDocument();
    const window = new EventTarget();
    window.i18n = i18n;
    const store = {getItem: key => storage.get(key) ?? null, setItem: (key, value) => storage.set(key, value)};
    const view = notice.create({document, window, storage: store});
    const [title, text, details, dismiss] = view.element.children;
    return {document, window, view, title, text, details, dismiss, storage};
}

test('the notice is mounted first in the page as an accessible status', () => {
    const {document, view, title, text, details, dismiss} = setup();
    assert.equal(document.body.children[0], view.element);
    assert.equal(view.element.attributes.role, 'status');
    assert.equal(view.element.hidden, false);
    assert.equal(title.textContent, 'Preview');
    assert.match(text.textContent, /preview of the new server/);
    assert.equal(details.hidden, true);
    assert.equal(dismiss.tagName, 'BUTTON');
    assert.equal(dismiss.type, 'button');
    assert.equal(dismiss.attributes['aria-label'], 'Dismiss preview notice');
});

test('features reported by the shim are listed once in a stable order', () => {
    const {window, details} = setup();
    for (const feature of ['insights', 'files', 'files', 'unknown']) {
        window.dispatchEvent(new CustomEvent('webssh:preview-unavailable', {detail: {feature}}));
    }
    assert.equal(details.hidden, false);
    assert.equal(details.textContent, 'Not available in this preview yet: Files, Session insights, Other functions');
});

test('dismissal is remembered for the tab and lifted by a newly reached feature', () => {
    const first = setup();
    first.view.report('files');
    first.dismiss.click();
    assert.equal(first.view.element.hidden, true);

    const reload = setup({storage: first.storage});
    assert.equal(reload.view.element.hidden, true);
    reload.view.report('files');
    assert.equal(reload.view.element.hidden, true, 'an already dismissed feature stays quiet');
    reload.view.report('smb');
    assert.equal(reload.view.element.hidden, false);
});

test('texts follow the page language and are set as text, never markup', () => {
    let language = 'en';
    const dictionaries = {
        de: {'previewNotice.title': 'Vorschau', 'previewNotice.feature.files': 'Dateien',
            'previewNotice.unavailable': 'In dieser Vorschau noch nicht verfügbar: {features}'},
    };
    const i18n = {t: key => dictionaries[language]?.[key] || key};
    const {window, view, title, details} = setup({i18n});
    view.report('files');
    assert.equal(title.textContent, 'Preview');
    language = 'de';
    window.dispatchEvent(new Event('languageChanged'));
    assert.equal(title.textContent, 'Vorschau');
    assert.equal(details.textContent, 'In dieser Vorschau noch nicht verfügbar: Dateien');
    assert.equal(Object.hasOwn(view.element, 'innerHTML'), false);
});

test('a broken stored value does not hide the notice', () => {
    const storage = new Map([[notice.STORAGE_KEY, '{not json']]);
    const {view} = setup({storage});
    assert.equal(view.element.hidden, false);
});

test('the built-in English fallback matches the English translations', () => {
    const fs = require('node:fs');
    const vm = require('node:vm');
    const english = {};
    vm.runInNewContext(fs.readFileSync('static/js/preview-notice-i18n.js', 'utf8'), {
        window: {i18n: {addTranslations(language, values) { if (language === 'en') Object.assign(english, values); }}},
    });
    const {view, title} = setup({i18n: {t: key => english[key] || key}});
    const fallback = setup();
    view.report('smb');
    fallback.view.report('smb');
    assert.equal(fallback.title.textContent, title.textContent);
    assert.equal(fallback.details.textContent, view.element.children[2].textContent);
});

// The server names the areas of the page in #websshPreview; they are
// listed from the start, and the sign-in page explains which accounts
// cannot sign in, in the browser's language.
test('the page configuration lists the server-named areas', () => {
    const document = fakeDocument();
    const window = new EventTarget();
    const config = {enabled: true, unavailable: ['files', 'automation', 'serverOps', 'bogus'], message: 'Preview'};
    const view = notice.create({document, window, storage: null, config});
    const [, text, details] = view.element.children;
    assert.match(text.textContent, /preview of the new server/);
    assert.equal(details.textContent, 'Not available in this preview yet: Files, Automation, Server operations');
});

test('the sign-in page names the accounts that cannot sign in', () => {
    const document = fakeDocument();
    document.documentElement = {lang: 'de'};
    const window = new EventTarget();
    const view = notice.create({document, window, storage: null, config: {enabled: true, unavailable: ['ldap', 'oidc', 'github']}});
    const [, text, details] = view.element.children;
    assert.match(text.textContent, /Konten aus LDAP, OIDC oder GitHub/);
    assert.equal(details.hidden, true);
});

test('the configuration is read from the page', () => {
    const document = fakeDocument();
    document.getElementById = id => (id === 'websshPreview' ? {textContent: '{"enabled":true,"unavailable":["smb"]}'} : null);
    const view = notice.create({document, window: new EventTarget(), storage: null});
    assert.equal(view.element.children[2].textContent, 'Not available in this preview yet: SMB shares');
    document.getElementById = () => ({textContent: '{broken'});
    const broken = notice.create({document, window: new EventTarget(), storage: null});
    assert.equal(broken.element.children[2].hidden, true);
});
