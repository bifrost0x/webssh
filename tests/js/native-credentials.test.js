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
 let current=true;const target={host:'server',port:22,username:'operator'};const sent=[];
 const client=nativeClient(async(path,options)=>{sent.push({path,body:JSON.parse(options.body)});if(path.endsWith('/intents'))return {ok:true,json:async()=>({intent:'target-intent'})};current=false;return {ok:true,json:async()=>({credential_target_token:'late-token'})};});
 await assert.rejects(client.authorizeTarget('named',target,()=>current),{name:'AbortError'});
 assert.deepEqual(sent.map(item=>item.path),['/api/credentials/intents','/api/credentials/authorize-target']);
 assert.deepEqual(sent[0].body,{operation:'native',mutation:{method:'authorize_target',credential_id:'named',target,confirm_target:true}});
 assert.deepEqual(sent[1].body,{credential_id:'named',target,confirm_target:true,intent:'target-intent'});
});

test('binding a saved password retries once with a grant for the exact intent',async()=>{
 const requests=[];
 const context={window:{},document:{addEventListener(){},querySelector(){return null;},activeElement:null},DOMException};
 context.fetch=async(path,options)=>{
  requests.push({path,body:JSON.parse(options.body),headers:options.headers});
  if(path.endsWith('/intents'))return {ok:true,json:async()=>({intent:'bind-intent'})};
  if(!options.headers['X-WebSSH-Step-Up'])return {ok:false,status:403,json:async()=>({code:'step_up_required'})};
  return {ok:true,json:async()=>({credential_target_token:'token'})};
 };
 const authorized=[];
 context.window.WebSSHSecurityUI={createAccountStepUpClient:()=>({authorize:async(action,target)=>{authorized.push([action,target]);return 'grant-value';},header:grant=>({'X-WebSSH-Step-Up':grant})})};
 vm.runInNewContext(fs.readFileSync('static/js/native-credentials.js','utf8'),context);
 const result=await context.window.NativeCredentials.authorizeTarget('named',{host:'server',port:22,username:'operator'});
 assert.equal(result.credential_target_token,'token');
 assert.deepEqual(authorized,[['credentials.vault','bind-intent']]);
 assert.deepEqual(requests.map(item=>item.path),['/api/credentials/intents','/api/credentials/authorize-target','/api/credentials/authorize-target']);
 assert.equal(requests[2].headers['X-WebSSH-Step-Up'],'grant-value');
 assert.equal(requests[2].body.intent,'bind-intent');
});

test('cancelled reauthentication does not retry the binding',async()=>{
 const requests=[];
 const context={window:{},document:{addEventListener(){},querySelector(){return null;},activeElement:null},DOMException};
 context.fetch=async(path,options)=>{requests.push(path);if(path.endsWith('/intents'))return {ok:true,json:async()=>({intent:'bind-intent'})};return {ok:false,status:403,json:async()=>({code:'step_up_required'})};};
 context.window.WebSSHSecurityUI={createAccountStepUpClient:()=>({authorize:async()=>null,header:grant=>({'X-WebSSH-Step-Up':grant})})};
 vm.runInNewContext(fs.readFileSync('static/js/native-credentials.js','utf8'),context);
 await assert.rejects(context.window.NativeCredentials.mutate('assign',{resource_id:'p1',credential_id:'named'}),{name:'AbortError'});
 assert.deepEqual(requests,['/api/credentials/intents','/api/credentials/assign']);
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

test('every saved-password target authorization goes through the step-up flow',()=>{
 const source=fs.readFileSync('static/js/native-credentials.js','utf8');
 // Only authorizeTarget() may call the endpoint; it prepares an intent and retries with a grant.
 assert.equal(source.split("'/api/credentials/authorize-target'").length-1,1);
 assert.match(source,/async function authorizeTarget[\s\S]*?\/api\/credentials\/intents[\s\S]*?withStepUp/);
});

test('concurrent password state loads share one request and later loads fetch again',async()=>{
 const pending=[];let calls=0;
 const client=nativeClient(path=>{calls++;assert.equal(path,'/api/credentials/state');return new Promise(resolve=>pending.push(resolve));});
 const first=client.load(),second=client.load(),third=client.load();
 assert.equal(calls,1);
 pending[0]({ok:true,json:async()=>({enabled:true,credentials:[{id:'a'}]})});
 const results=await Promise.all([first,second,third]);
 assert.deepEqual(results.map(result=>result.credentials[0].id),['a','a','a']);
 const later=client.load();assert.equal(calls,2);
 pending[1]({ok:true,json:async()=>({enabled:true,credentials:[{id:'b'}]})});
 assert.equal((await later).credentials[0].id,'b');
});

test('a load after a mutation does not join a request that started before it',async()=>{
 const pending=[];const paths=[];const intentBodies=[];
 const client=nativeClient((path,options)=>{paths.push(path);if(path.endsWith('/intents'))intentBodies.push(JSON.parse(options.body));if(path.endsWith('/intents'))return Promise.resolve({ok:true,json:async()=>({intent:'one'})});if(options.method==='POST')return Promise.resolve({ok:true,json:async()=>({enabled:true,credentials:[{id:'created'}]})});return new Promise(resolve=>pending.push(resolve));});
 const stale=client.load();
 await client.mutate('create',{name:'Named',password:'secret'});
 const fresh=client.load();
 assert.equal(paths.filter(path=>path==='/api/credentials/state').length,2);
 pending[1]({ok:true,json:async()=>({enabled:true,credentials:[{id:'fresh'}],profiles:[{id:'p1',credential_assignment:'fresh-assignment'}]})});
 assert.equal((await fresh).credentials[0].id,'fresh');
 pending[0]({ok:true,json:async()=>({enabled:true,credentials:[{id:'stale'}],profiles:[{id:'p1',credential_assignment:'stale-assignment'}]})});
 assert.equal((await stale).credentials[0].id,'stale');
 // The late stale response must not replace the stored state used by later mutations.
 await client.mutate('assign',{resource_id:'p1',credential_id:'c1'});
 assert.equal(intentBodies.at(-1).mutation.expected_assignment,'fresh-assignment');
});

test('a failed shared load rejects every waiting caller and the next load retries',async()=>{
 let calls=0;
 const client=nativeClient(async()=>{calls++;if(calls===1)return {ok:false,status:500,json:async()=>({code:'busy'})};return {ok:true,json:async()=>({enabled:true,credentials:[]})};});
 const results=await Promise.allSettled([client.load(),client.load()]);
 assert.deepEqual(results.map(result=>result.status),['rejected','rejected']);
 assert.equal(calls,1);
 assert.deepEqual((await client.load()).credentials,[]);
 assert.equal(calls,2);
});

