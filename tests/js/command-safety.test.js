const test = require('node:test');
const assert = require('node:assert/strict');
const launcher = require('../../static/js/session-command-launcher.js');
const catalog = require('../../app/resources/commands/system_commands.json');

test('only the exact known template receives an impact label; custom and edited text stays unclassified', () => {
    const original = catalog.find(item => item.id === 'sys-016');
    const entries = launcher.buildLauncherEntries([original, {...original, isSystem:false}, {...original, parameters:'-h; reboot'}], []);
    assert.equal(entries[0].safety?.impact, 'read-only');
    assert.equal(entries[1].safety, null);
    assert.equal(entries[2].safety, null);
});

test('focused translation bundles merge supported languages and retain fallback and language switching', () => {
    const fs = require('node:fs');
    const vm = require('node:vm');
    const window = {dispatchEvent() {}};
    const document = {addEventListener() {}, documentElement:{}, querySelectorAll:()=>[], querySelector:()=>null, title:''};
    vm.runInNewContext(fs.readFileSync('static/js/i18n.js', 'utf8'), {window, document, CustomEvent:function() {}});
    assert.equal(typeof window.i18n.addTranslations, 'function');
    assert.equal(window.i18n.addTranslations('en', {'test.bundle':'English', 'test.fallback':'Fallback'}), true);
    assert.equal(window.i18n.addTranslations('de', {'test.bundle':'Deutsch'}), true);
    assert.equal(window.i18n.addTranslations('__proto__', {'test.bundle':'Invalid'}), false);
    assert.equal(window.i18n.addTranslations('xx', {'test.bundle':'Invalid'}), false);
    assert.equal(window.i18n.setLanguage('de'), true);
    assert.equal(window.i18n.t('test.bundle'), 'Deutsch');
    assert.equal(window.i18n.t('test.fallback'), 'Fallback');
    assert.equal(window.i18n.t('commands.noCommands'), 'Keine Befehle gefunden');
    assert.equal(window.i18n.setLanguage('en'), true);
    assert.equal(window.i18n.t('test.bundle'), 'English');
});

test('impact guidance and template mutability remain distinct in all six languages', () => {
    const fs = require('node:fs');
    const vm = require('node:vm');
    const window = {};
    vm.runInNewContext(fs.readFileSync('static/js/i18n.js', 'utf8'), {window, document:{addEventListener() {}}});
    vm.runInNewContext(fs.readFileSync('static/js/command-safety-i18n.js', 'utf8'), {window});
    for (const language of ['en','de','fr','es','vi','zh']) {
        window.i18n.currentLang = language;
        const keys = ['recommended', 'all', 'read-only','changes-system','deletes-data','network-load','unknown','requires','prerequisites','scope'];
        for (const key of keys) assert.notEqual(window.i18n.t(`commandSafety.${key}`), `commandSafety.${key}`, language);
        assert.notEqual(window.i18n.t('commands.systemSource'), window.i18n.t('commandSafety.read-only'));
    }
});

test('customer recovery and continuity guidance covers dynamic and visible states in every language', () => {
    const fs = require('node:fs');
    const vm = require('node:vm');
    const file = 'static/js/customer-workflows-i18n.js';
    assert.equal(fs.existsSync(file), true, 'Customer workflow dictionary must be shipped');
    const dictionaries = {};
    vm.runInNewContext(fs.readFileSync(file, 'utf8'), {window:{i18n:{addTranslations(language, values) {dictionaries[language]=values;}}}});
    const required = ['continuity.none','continuity.transport','continuity.tmux','continuity.tmuxDisconnected','continuity.normal','continuity.disconnected','permission','unknown','conflict','source','failure','extraWindowLayout','key_required','password_required','interactive','nextSteps'];
    const controller = fs.readFileSync('static/js/customer-workflows.js','utf8');
    for (const match of controller.matchAll(/\bt\('([a-zA-Z]+)'\)/g)) required.push(match[1]);
    for (const language of ['en','de','fr','es','vi','zh']) {
        for (const key of required) assert.ok(dictionaries[language][`customer.${key}`]?.trim(), `${language}: ${key}`);
        if (language !== 'en') for (const [key,value] of Object.entries(dictionaries[language])) assert.notEqual(value,dictionaries.en[key],`${language}: ${key} must be translated`);
    }
    assert.match(dictionaries.en['customer.presetsHint'], /never connect/i);
    assert.match(dictionaries.en['customer.excluded'], /passwords.*SSH private keys/i);
    assert.match(dictionaries.en['customer.unknown'], /before.*retry/i);
});
