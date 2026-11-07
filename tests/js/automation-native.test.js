const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
test('native automation is a reusable workspace with inline command editing and a schedule inspector',()=>{
 const html=fs.readFileSync('templates/_automation_workspace.html','utf8');
 assert.match(html,/id="automationScheduleInspector"/);
 assert.match(html,/id="scheduleFrequency"/);
 assert.match(html,/data-inspector="step"/);
 assert.doesNotMatch(html,/data-auto-tab="credentials"/);
 const js=fs.readFileSync('static/js/automation.js','utf8');
 assert.match(js,/WebSSHAutomation/);
 assert.match(js,/nativeCredentials/);
});

const vm=require('node:vm');
const sandbox={window:{},document:{getElementById:()=>null}};
vm.runInNewContext(fs.readFileSync('static/js/automation.js','utf8'),sandbox);
const builder=sandbox.window.AutomationSchedule;
test('calendar frequencies derive exact five-field cron without browser timezone arithmetic',()=>{
 for(const [options,cron] of [
  [{frequency:'hourly',minute:'17'},'17 * * * *'],
  [{frequency:'daily',time:'00:05'},'5 0 * * *'],
  [{frequency:'weekdays',time:'23:59'},'59 23 * * 1-5'],
  [{frequency:'weekly',time:'02:30',weekday:'0'},'30 2 * * 0'],
  [{frequency:'monthly',time:'09:00',monthday:'31'},'0 9 31 * *'],
 ]) {assert.equal(builder.cron(options),cron);assert.equal(builder.cron(builder.parse(cron)),cron);}
});
test('advanced expressions survive edits verbatim and cannot be misclassified',()=>{
 for(const cron of ['*/15 8-18 * * 1-5','0 9 1 * 1','0 9 * * 7','0 9 * JAN MON','00 09 * * *',' 0 9 * * * ','invalid']) {
  assert.equal(builder.parse(cron).frequency,'custom');
  assert.equal(builder.cron(builder.parse(cron)),cron);
 }
});
test('invalid calendar values cannot generate unintended jobs',()=>{
 for(const options of [{frequency:'hourly',minute:'60'},{frequency:'hourly',minute:''},{frequency:'daily',time:'24:00'},{frequency:'daily',time:''},{frequency:'monthly',monthday:'0'},{frequency:'weekly',weekday:'7'}]) assert.equal(builder.cron(options),null);
});
