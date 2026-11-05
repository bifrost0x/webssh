const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const root = path.join(__dirname, '../..');
const source = fs.readFileSync(path.join(root,'static/js/automation-i18n.js'),'utf8');
const html = fs.readFileSync(path.join(root,'templates/_automation_workspace.html'),'utf8');
const controller = fs.readFileSync(path.join(root,'static/js/automation.js'),'utf8');
const keys = new Set([...html.matchAll(/data-auto-i18n="([^"]+)"/g), ...controller.matchAll(/\btr\('([^']+)'/g)].map(match=>match[1]));
for (const status of ['queued','running','succeeded','failed','unknown','cancelled','skipped']) keys.add(`state.${status}`);
for (const state of ['waiting','running','missed','overlap','skipped','needs_review','unknown','succeeded','failed','cancelled','paused']) keys.add(`scheduleState.${state}`);
for (const method of ['password','ldap','totp','passkey','oidc','github','bootstrap']) keys.add(`method.${method}`);
for (const frequency of ['hourly','daily','weekdays','weekly','monthly','custom']) keys.add(`summary.${frequency}`);
for (const stage of ['editor','targets','schedule']) keys.add(`stageHint.${stage}`);
for (const reason of ['confirmed','unconfirmed','nonzero_exit','timeout','cancelled','output_limit','channel_lost','acknowledgement_lost','dispatch_failed','run_interrupted','legacy','truncated','pending','empty']) keys.add(`diagnostic.${reason}`);
for (const key of ['nextTargets','nextSchedule']) keys.add(key);
for (const lang of ['en','de']) {
    test(`automation has complete ${lang} labels and status messages`, () => {
        const window = {i18n:{getLanguage:()=>lang}};
        vm.runInNewContext(source,{window});
        for (const key of keys) {
            assert.notEqual(window.AutomationText.t(key),key,`Missing ${lang} ${key}`);
        }
        assert.match(window.AutomationText.t('hostCount',{count:7}),/7/);
        assert.doesNotMatch(window.AutomationText.t('typeCount',{count:7}),/\{count\}/);
    });
}
test('automation falls back to English for other application locales',()=>{
    const window={i18n:{getLanguage:()=> 'fr'}};
    vm.runInNewContext(source,{window});
    assert.equal(window.AutomationText.t('runs'),'Runs');
});
