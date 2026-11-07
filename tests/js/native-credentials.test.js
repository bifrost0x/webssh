const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
test('native password state uses enabled policy and exact confirmed destination without legacy unlock', () => {
 const context = {window:{},document:{addEventListener(){}}};
 vm.runInNewContext(fs.readFileSync('static/js/credential-picker.js','utf8'),context);
 const target={host:'nas',username:'alice',share:'docs',domain:'home'};
 const state={enabled:true,profiles:[{id:'smb:1',...target,credential_id:'named',credential_valid:true}],credentials:[{id:'named',uses:[{id:'smb:1',valid:true}]}]};
 assert.equal(context.window.CredentialPicker.available(state,'smb:1',target),true);
 assert.equal(context.window.CredentialPicker.available(state,'smb:1',{...target,domain:'other'}),false);
 state.enabled=false;
 assert.equal(context.window.CredentialPicker.available(state,'smb:1',target),false);
});
test('native resource is mounted with no credential iframe',()=>{
 const source=fs.readFileSync('static/js/credential-picker.js','utf8');
 assert.doesNotMatch(source,/createElement\('iframe'\)/);
 assert.match(fs.readFileSync('templates/index.html','utf8'),/credentialManagementView/);
});
function nativeClient(fetch){
 const context={window:{},document:{addEventListener(){},querySelector(){return null;}},fetch,DOMException};
 vm.runInNewContext(fs.readFileSync('static/js/native-credentials.js','utf8'),context);
 return context.window.NativeCredentials;
}
test('native mutation consumes exact intent without account challenge and clears plaintext draft',async()=>{
 const requests=[];const client=nativeClient(async(path,options)=>{requests.push({path,body:JSON.parse(options.body),headers:options.headers});return {ok:true,json:async()=>path.endsWith('/intents')?{intent:'single-use'}:{enabled:true,credentials:[]}};});
 const payload={name:'Named',password:'sensitive'};await client.mutate('create',payload);
 assert.deepEqual(requests.map(request=>request.path),['/api/credentials/intents','/api/credentials']);
 assert.equal(requests[0].body.operation,'native');assert.equal(requests[0].body.mutation.password,'sensitive');assert.equal(requests[1].body.intent,'single-use');assert.equal(payload.password,'');assert.equal(requests[1].headers['X-WebSSH-Step-Up'],undefined);
});
test('late native intent cannot mutate a cancelled destination and clears password',async()=>{
 let current=true;let requests=0;const client=nativeClient(async()=>{requests++;current=false;return {ok:true,json:async()=>({intent:'stale'})};});const payload={password:'sensitive'};
 await assert.rejects(client.mutate('create',payload,null,()=>current),{name:'AbortError'});assert.equal(requests,1);assert.equal(payload.password,'');
});
test('target authorization binds exact destination and rejects late result',async()=>{
 let current=true;const target={host:'server',port:22,username:'operator'};let sent;
 const client=nativeClient(async(path,options)=>{sent={path,body:JSON.parse(options.body)};current=false;return {ok:true,json:async()=>({credential_target_token:'late-token'})};});
 await assert.rejects(client.authorizeTarget('named',target,()=>current),{name:'AbortError'});assert.equal(sent.path,'/api/credentials/authorize-target');assert.deepEqual(sent.body,{credential_id:'named',target,confirm_target:true});
});

test('password API gives a sign-in message for expired HTML sessions',async()=>{
 const client=nativeClient(async()=>({ok:true,status:200,redirected:true,url:'https://host.invalid/webssh/login?next=/api/credentials/state',json:async()=>{throw new SyntaxError('Unexpected token <');}}));
 await assert.rejects(client.load(),/sign-in session expired/i);
});

test('password API rejects malformed proxy responses without leaking parser details',async()=>{
 for(const response of [
  {ok:false,status:502,json:async()=>{throw new SyntaxError('private proxy response');}},
  {ok:true,status:200,json:async()=>null},
  {ok:true,status:200,json:async()=>[]}
 ]){
  const client=nativeClient(async()=>response);
  await assert.rejects(client.load(),error=>/Passwords could not be saved/.test(error.message)&&!error.message.includes('private proxy'));
 }
});
