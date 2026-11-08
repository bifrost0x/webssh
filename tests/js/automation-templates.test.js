const {test}=require('node:test');const assert=require('node:assert/strict');const catalog=require('../../static/js/automation-templates.js');
test('workflow examples provide complete bilingual metadata and independent drafts',()=>{
 const list=catalog.list();assert.equal(list.length,23);assert.equal(new Set(list.map(t=>t.id)).size,list.length);
 for(const item of list){
  const draft=catalog.create(item.id);assert.ok(draft.steps.length>0&&draft.steps.length<=20);
  assert.equal(item.stepCount,draft.steps.length);
  assert.equal(draft.steps[0].name,'Check prerequisites');
  assert.equal(draft.steps[0].sudo,false);
  assert.match(draft.steps[0].command,/Required command is missing/);
  assert.ok(!draft.steps[0].command.includes('undefined'));
  for(const language of ['en','de']){assert.ok(item.title[language]);assert.ok(item.requires[language]);}
  for(const step of draft.steps){assert.ok(step.name);assert.ok(step.command);assert.ok(step.timeout>=1&&step.timeout<=300);if(step.sudo)assert.equal(draft.writes,true);}
  const original=draft.steps[0].command;draft.steps[0].command='changed';assert.equal(catalog.create(item.id).steps[0].command,original);
  assert.equal(draft.id,item.id);
 }
 assert.equal(catalog.create('missing'),null);
});
