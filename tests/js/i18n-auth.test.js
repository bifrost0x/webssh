const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync('static/js/i18n-auth.js', 'utf8');

function loadAuthI18n(localStorage) {
    const document = {
        documentElement: {},
        title: '',
        addEventListener() {},
        querySelector() { return null; },
        querySelectorAll() { return []; },
    };
    const events = [];
    const window = {
        localStorage,
        dispatchEvent(event) { events.push(event); },
    };
    const context = vm.createContext({
        CustomEvent: class CustomEvent {
            constructor(name, options) {
                this.name = name;
                this.detail = options.detail;
            }
        },
        document,
        window,
    });
    vm.runInContext(source, context);
    return { events, window };
}

test('the auth bundle preserves all locales and representative page translations', () => {
    const { events, window } = loadAuthI18n({
        getItem() { return 'en'; },
        setItem() {},
    });

    assert.deepEqual(
        Array.from(window.i18n.getLanguages(), language => language.code),
        ['en', 'vi', 'de', 'fr', 'es', 'zh'],
    );
    assert.equal(window.i18n.t('auth.login'), 'Sign In');
    assert.equal(window.i18n.t('security.methodPasskey'), 'Passkey');
    assert.equal(window.i18n.t('navigation.sshWorkspaces'), 'SSH Workspaces');
    assert.equal(window.i18n.setLanguage('de'), true);
    assert.equal(window.i18n.getLanguage(), 'de');
    assert.equal(window.i18n.t('auth.login'), 'Anmelden');
    assert.equal(events.at(-1).name, 'languageChanged');
    assert.equal(events.at(-1).detail.lang, 'de');
});

test('the auth bundle still works when browser storage is blocked', () => {
    const { window } = loadAuthI18n({
        getItem() { throw new Error('storage denied'); },
        setItem() { throw new Error('storage denied'); },
    });

    assert.equal(window.i18n.getLanguage(), 'en');
    assert.equal(window.i18n.setLanguage('fr'), true);
    assert.equal(window.i18n.getLanguage(), 'fr');
    assert.equal(window.BrowserPreferences.set('example', 'value'), false);
});
