// The one-time upgrade notice (static/js/onboarding.js) is shown in every
// interface language: each key it reads exists in every locale with a
// nonempty text, and its English fallbacks are the English texts.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {LOCALES, localeTable} = require('./i18n-locales.js');

const source = fs.readFileSync(path.join(__dirname, '../../static/js/onboarding.js'), 'utf8');
const notice = source.slice(source.indexOf('function showUpgradeNotice'), source.indexOf('// A language switch redraws'));

// Keys with their English fallback: t('key', 'fallback') and the
// ['key', 'fallback'] pairs of the benefit list. Fallbacks may hold an
// escaped apostrophe.
function noticeKeys() {
    const keys = new Map();
    for (const [, key, fallback] of notice.matchAll(/(?:t\(|\[)'((?:upgradeNotice|settings)\.[\w.]+)',\s*'((?:[^'\\]|\\.)*)'/g)) {
        keys.set(key, fallback.replace(/\\(.)/g, '$1'));
    }
    return keys;
}

test('the notice reads its texts, including the support section', () => {
    const keys = noticeKeys();
    for (const key of ['upgradeNotice.title', 'upgradeNotice.body', 'upgradeNotice.report', 'upgradeNotice.confirm',
        'upgradeNotice.supportTitle', 'upgradeNotice.support']) {
        assert.ok(keys.has(key), `${key} is not read by the notice`);
    }
});

test('every language has every key of the upgrade notice', () => {
    const table = localeTable();
    assert.deepEqual([...LOCALES].sort(), ['de', 'en', 'es', 'fr', 'vi', 'zh']);
    for (const key of noticeKeys().keys()) {
        for (const locale of LOCALES) {
            const value = table[locale][key];
            assert.equal(typeof value, 'string', `${locale}: ${key} missing`);
            assert.ok(value.trim(), `${locale}: ${key} empty`);
        }
    }
});

test('no language has an upgrade notice key the notice does not read', () => {
    const used = noticeKeys();
    for (const [locale, entries] of Object.entries(localeTable())) {
        const unused = Object.keys(entries).filter(key => key.startsWith('upgradeNotice.') && !used.has(key));
        assert.deepEqual(unused, [], locale);
    }
});

test('the English fallbacks match the English texts', () => {
    const english = localeTable().en;
    for (const [key, fallback] of noticeKeys()) assert.equal(fallback, english[key], key);
});
