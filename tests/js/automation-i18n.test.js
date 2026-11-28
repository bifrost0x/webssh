const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {LOCALES, localeTable, runI18n} = require('./i18n-locales.js');
const root = path.join(__dirname, '../..');
const html = fs.readFileSync(path.join(root,'internal/httpapi/pages/automation_workspace.gohtml'),'utf8');
const controller = fs.readFileSync(path.join(root,'static/js/automation.js'),'utf8');
const keys = new Set([...html.matchAll(/data-auto-(?:i18n|placeholder|label)="([^"]+)"/g), ...controller.matchAll(/\btr\('([^']+)'/g)].map(match=>match[1]));
for (const status of ['queued','running','succeeded','failed','unknown','cancelled','skipped']) keys.add(`state.${status}`);
for (const state of ['waiting','running','missed','overlap','skipped','needs_review','unknown','succeeded','failed','cancelled','paused']) keys.add(`scheduleState.${state}`);
for (const method of ['password','ldap','totp','passkey','oidc','github','bootstrap']) keys.add(`method.${method}`);
for (const frequency of ['hourly','daily','weekdays','weekly','monthly','custom']) keys.add(`summary.${frequency}`);
for (const stage of ['editor','targets','schedule']) keys.add(`stageHint.${stage}`);
for (const reason of ['confirmed','unconfirmed','nonzero_exit','timeout','cancelled','output_limit','channel_lost','acknowledgement_lost','dispatch_failed','run_interrupted','legacy','truncated','pending','empty']) keys.add(`diagnostic.${reason}`);
for (const reason of ['host_key_required','host_key_changed','host_key_revoked','authentication_failed','connect_timeout','connection_failed','run_interrupted','tailscale_route_restricted']) keys.add(`result.${reason}`);
for (const key of ['nextTargets','nextSchedule']) keys.add(key);
const table = localeTable();

for (const lang of LOCALES) {
    test(`automation has complete ${lang} labels and status messages`, () => {
        for (const key of keys) {
            assert.ok(table[lang][`automation.${key}`]?.trim(), `Missing ${lang} automation.${key}`);
        }
        if (lang !== 'en') {
            const untranslated = [...keys].filter(key => !/^(?:weekday|frequency)\./.test(key)
                && table[lang][`automation.${key}`] === table.en[`automation.${key}`]
                && /[a-z]{4}/.test(table.en[`automation.${key}`]) && !/^[{}\w\s.:·/-]*(?:SSH|cron|JSON|CSV)/.test(table.en[`automation.${key}`]));
            assert.ok(untranslated.length < 15, `${lang}: ${untranslated.length} strings left in English: ${untranslated.slice(0, 15).join(', ')}`);
        }
    });
}

test('the automation controller uses the shared translation runtime', () => {
    assert.match(controller, /window\.i18n\.t\(`automation\.\$\{key\}`\)/);
    assert.doesNotMatch(controller, /AutomationText|getLanguage\(\) === 'de'/);
    const window = {dispatchEvent() {}};
    runI18n({window, document: {addEventListener() {}}, CustomEvent: class {}});
    window.i18n.currentLang = 'fr';
    assert.notEqual(window.i18n.t('automation.runs'), 'Runs');
    window.i18n.currentLang = 'zh';
    assert.notEqual(window.i18n.t('automation.runs'), 'Runs');
});
