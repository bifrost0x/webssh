(function () {
 'use strict';
 const t=(key,fallback)=>{const value=window.i18n?.t(key);return value&&value!==key?value:fallback;};
 const root=()=> (document.querySelector('meta[name="app-root"]')?.content||'').replace(/\/$/,'');
 const el=(tag,text,cls)=>{const node=document.createElement(tag); if(text)node.textContent=text;if(cls)node.className=cls;return node;};
 let state=null, loadGeneration=0;
 async function api(path,options={}) {
  const response=await fetch(root()+path,{credentials:'same-origin',cache:'no-store',...options,headers:{Accept:'application/json','Content-Type':'application/json','X-CSRFToken':document.querySelector('meta[name="csrf-token"]')?.content||'',...options.headers},body:options.body?JSON.stringify(options.body):undefined});
  if(response.status===401||(response.redirected&&/\/login(?:[?#]|$)/.test(response.url||'')))throw new Error(t('credentials.sessionExpired','Your sign-in session expired. Sign in again before saving.'));
  let data;
  try{data=await response.json();}catch{throw new Error(t('credentials.failed','Passwords could not be saved. Check your authorization and try again.'));}
  if(!data||typeof data!=='object'||Array.isArray(data))throw new Error(t('credentials.failed','Passwords could not be saved. Check your authorization and try again.'));
  if(!response.ok){const messages={step_up_failed:['credentials.identityFailed','Identity verification failed. Check your WebSSH account password or verification code and try again.'],rate_limited:['credentials.rateLimited','Too many attempts. Wait a minute and try again.'],busy:['credentials.rateLimited','Too many attempts. Wait a minute and try again.'],invalid_intent:['credentials.changed','The saved destination changed. Reload it and review the assignment again.'],preview_changed:['credentials.assignmentChanged','The destination or its password assignment changed. Reload it and review the assignment again.'],replacement_confirmation_required:['credentials.assignmentChanged','The destination or its password assignment changed. Reload it and review the assignment again.'],credential_in_use:['credentials.inUse','Remove the host assignments before deleting this password.'],https_required:['credentials.httpsRequired','Password management requires HTTPS.'],authentication_session_invalid:['credentials.sessionExpired','Your sign-in session expired. Sign in again before saving.'],authentication_required:['credentials.sessionExpired','Your sign-in session expired. Sign in again before saving.'],credentials_disabled:['credentials.disabled','Password storage is disabled by the administrator.'],step_up_required:['credentials.identityFailed','Identity verification failed. Check your WebSSH account password or verification code and try again.']};const message=messages[data.code]||['credentials.failed','Passwords could not be saved. Check your authorization and try again.'];const error=new Error(t(message[0],message[1]));error.code=data.code;throw error;}
  return data;
 }
 function question(title,{secret=false,choices=null,confirmation=false,description='',acceptLabel=null,heading=null}={}) {
  return new Promise(resolve=>{
   const opener=document.activeElement;
   const dialog=el('dialog',null,'credential-picker-dialog credential-question');const form=el('form');form.method='dialog';dialog.setAttribute('aria-label',title);
   if(heading){const title=el('h2',heading);title.id='credential-question-title';dialog.setAttribute('aria-labelledby',title.id);form.append(title);}if(description){const detail=el('p',description,'credential-hint');detail.style.whiteSpace='pre-line';form.append(detail);}const label=el('label',title);const input=el(choices?'select':'input');input.className='form-control';
   if(choices)choices.forEach(choice=>{const option=el('option',typeof choice==='object'?choice.label:choice);option.value=typeof choice==='object'?choice.value:choice;input.append(option);});
   else {input.type=secret?'password':'text';input.autocomplete=secret?'current-password':'on';}
   if(confirmation)input.hidden=true;label.append(input);const actions=el('div',null,'credential-picker-controls');const cancel=el('button',t('common.cancel','Cancel'),'btn btn-secondary');cancel.type='button';
   const accept=el('button',acceptLabel||t('common.confirm','Confirm'),'btn btn-primary');accept.type='submit';actions.append(cancel,accept);form.append(label,actions);dialog.append(form);document.body.append(dialog);
   let result=null;cancel.onclick=()=>dialog.close();form.onsubmit=event=>{event.preventDefault();result=confirmation?true:input.value;input.value='';dialog.close();};
   dialog.onclose=()=>{input.value='';dialog.remove();if(opener?.isConnected&&typeof opener.focus==='function')opener.focus();resolve(result);};dialog.addEventListener('keydown',event=>event.stopPropagation());dialog.showModal();(confirmation?cancel:input).focus();
  });
 }
 async function confirmReplacements(entries){
  if(!entries.length)return true;
  const lines=entries.map(({resource,oldName,newName})=>(resource.name||resource.id)+': '+oldName+' → '+newName).join('\n');
  return await question(t('credentials.replaceAssignmentConfirm','Replace the saved password assignment?'),{confirmation:true,description:t('credentials.onePerHost','Each saved resource uses one password. These assignments will be replaced:')+'\n'+lines})===true;
 }
 async function mutate(method,payload={},id=null,current=()=>true,replacementApproved=false) {
  try {
   if(!current())throw new DOMException('Cancelled','AbortError');
   if(['assign','create'].includes(method)&&payload.resource_id){
    const resource=payload.target?.credential_assignment!==undefined?payload.target:state?.profiles?.find(item=>item.id===payload.resource_id);
    if(resource?.credential_assignment!==undefined)payload.expected_assignment=resource.credential_assignment;
    const oldId=resource?.credential_id;
    if(oldId&&(method==='create'||(payload.credential_id&&payload.credential_id!==oldId))){
     if(!replacementApproved&&!await confirmReplacements([{resource,oldName:state?.credentials?.find(item=>item.id===oldId)?.name||t('credentials.unavailableAssignment','Assigned password unavailable'),newName:method==='create'?payload.name:state?.credentials?.find(item=>item.id===payload.credential_id)?.name||payload.credential_id}]))throw new DOMException('Cancelled','AbortError');
     if(!current())throw new DOMException('Cancelled','AbortError');
     payload.replace_credential_id=oldId;
    }
   }
   const mutation={method,...payload,...(id?{credential_id:id}:{})};
   const intent=await api('/api/credentials/intents',{method:'POST',body:{operation:'native',mutation}});
   if(!current())throw new DOMException('Cancelled','AbortError');
   const path=method==='create_for_resource'?'/api/credentials/create-for-resource':method==='create'?'/api/credentials':method==='assign'?'/api/credentials/assign':method==='import'?'/api/credentials/import-legacy':'/api/credentials/'+encodeURIComponent(id);
   ++loadGeneration;state=await withStepUp(intent.intent,current,headers=>api(path,{method:method==='update'?'PATCH':method==='delete'?'DELETE':'POST',headers,body:{...payload,intent:intent.intent}}));++loadGeneration;if(!current())throw new DOMException('Cancelled','AbortError');return state;
  } finally {if(payload.password)payload.password='';if(payload.passphrase)payload.passphrase='';}
 }
 async function authorizeTarget(credentialId,target,current=()=>true){
  if(!current())throw new DOMException('Cancelled','AbortError');
  const body={credential_id:credentialId,target,confirm_target:true};
  const intent=await api('/api/credentials/intents',{method:'POST',body:{operation:'native',mutation:{method:'authorize_target',...body}}});
  if(!current())throw new DOMException('Cancelled','AbortError');
  const result=await withStepUp(intent.intent,current,headers=>api('/api/credentials/authorize-target',{method:'POST',headers,body:{...body,intent:intent.intent}}));
  if(!current())throw new DOMException('Cancelled','AbortError');return result;
 }
 const base64UrlBytes=value=>Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/')),character=>character.charCodeAt(0));
 const base64Url=value=>btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
 const methodLabels={password:['security.methodPassword','WebSSH password'],ldap:['security.methodLdap','LDAP password'],totp:['security.methodTotp','Authenticator app'],passkey:['security.methodPasskey','Passkey'],bootstrap:['security.methodBootstrap','Enrollment code'],oidc:['security.methodOidc','Identity provider'],github:['security.methodGithub','GitHub']};
 // Reauthenticate for exactly this intent. The server accepts the retry only
 // with a grant bound to the same intent and browser authentication session.
 async function stepUpHeader(token,current){
  const security=window.WebSSHSecurityUI;
  if(!security?.createAccountStepUpClient)throw new Error(t('credentials.failed','Passwords could not be saved. Check your authorization and try again.'));
  let popup=null;
  const guard=()=>{if(!current())throw new DOMException('Cancelled','AbortError');};
  const client=security.createAccountStepUpClient({
   api:async(path,options)=>{guard();const result=await api(path,options);guard();return result;},
   chooseMethod:methods=>{guard();return question(t('credentials.confirmIdentity','Confirm your identity'),{choices:methods.map(method=>({value:method,label:t(...(methodLabels[method]||[method,method]))}))});},
   requestSecret:method=>{guard();return question(method==='totp'||method==='bootstrap'?t('credentials.accountCode','Account verification code'):t('credentials.accountPassword','WebSSH account password'),{secret:true,heading:t('credentials.confirmIdentity','Confirm your identity')});},
   getPasskeyAssertion:options=>{guard();return navigator.credentials.get({publicKey:{...options,challenge:base64UrlBytes(options.challenge),allowCredentials:(options.allowCredentials||[]).map(item=>({...item,id:base64UrlBytes(item.id)}))}});},
   serializeCredential:credential=>({id:credential.id,rawId:base64Url(credential.rawId),type:credential.type,authenticatorAttachment:credential.authenticatorAttachment,clientExtensionResults:credential.getClientExtensionResults(),response:{clientDataJSON:base64Url(credential.response.clientDataJSON),authenticatorData:base64Url(credential.response.authenticatorData),signature:base64Url(credential.response.signature),userHandle:credential.response.userHandle?base64Url(credential.response.userHandle):null}}),
   openAuthorization:url=>{guard();popup=window.open(url,'webssh-credential-step-up','popup,width=720,height=760');if(!popup)throw new Error(t('credentials.popup','Allow the sign-in window and try again.'));}
  });
  try{const grant=await client.authorize('credentials.vault',token);guard();if(!grant)throw new DOMException('Cancelled','AbortError');return client.header(grant);}
  finally{popup?.close();}
 }
 async function withStepUp(token,current,send){
  try{return await send({});}
  catch(error){
   if(error?.code!=='step_up_required')throw error;
   const headers=await stepUpHeader(token,current);
   return await send(headers);
  }
 }
 async function load(){const generation=++loadGeneration;const data=await api('/api/credentials/state');if(generation===loadGeneration)state=data;return data;}
 function editor(container,item={},onSaved=()=>{},current=()=>true){
  container.replaceChildren();const form=el('form',null,'native-credential-editor');const active=()=>current()&&form.isConnected&&!container.hidden&&(!container.closest('#credentialManagementView')||!container.closest('#credentialManagementView').hidden);const title=el('h3',item.id?t('credentials.edit','Password details'):t('credentials.new','New password'));form.append(title);
  const fields={};[['name',t('credentials.name','Name'),'text'],['username',t('credentials.username','Suggested username'),'text'],['password',item.id?t('credentials.replace','Replace password (leave empty to keep)'):t('credentials.password','Password'),'password']].forEach(([key,text,type])=>{const label=el('label',text);const input=el('input');input.name=key;input.type=type;input.className='form-control';input.autocomplete=type==='password'?'new-password':'off';input.required=key==='name'||(key==='password'&&!item.id);if(type!=='password')input.value=item[key]||'';input.maxLength=key==='name'?120:4096;label.append(input);form.append(label);fields[key]=input;});
  const hint=el('p',t('credentials.writeOnly','Saved passwords are never displayed. Replacing one affects every listed assignment.'),'credential-hint');form.append(hint);
  if(item.id){const assignments=el('section',null,'credential-assignments');assignments.append(el('h4',t('credentials.assignmentsTitle','Assigned hosts')));if(!item.uses?.length)assignments.append(el('p',t('credentials.noAssignments','This password is not assigned to a host yet.'),'credential-hint'));const assign=el('button',t('credentials.assignHosts','Assign to hosts'),'btn btn-secondary');assign.type='button';assign.disabled=state?.enabled===false;assign.onclick=()=>{if(!clean())return;assignHosts(assignments,item,onSaved,active,clean);};assignments.append(assign);form.append(assignments);}if(item.uses?.length){const list=el('ul');item.uses.forEach(use=>{const li=el('li');const link=el('button',use.name||use.resource_id||use.id,'btn btn-secondary btn-sm');link.type='button';link.onclick=()=>window.dispatchEvent(new CustomEvent('webssh:credential-resource',{detail:use}));const unassign=el('button',t('credentials.unassign','Remove assignment'),'btn btn-secondary btn-sm');unassign.type='button';unassign.onclick=async()=>{if(form.dataset.assignmentsDirty==='true'){status.textContent=t('credentials.applyFirst','Apply or cancel your host assignment changes before saving password details.');return;}if(!clean())return;unassign.disabled=true;try{await mutate('assign',{resource_id:use.resource_id||use.id,credential_id:null,confirm_target:true},null,()=>active()&&clean());if(active())onSaved();}catch(error){if(error.name!=='AbortError')unassign.textContent=error.message;}finally{unassign.disabled=false;}};const resource=state?.profiles?.find(target=>target.id===(use.resource_id||use.id));li.append(link);if(resource)li.append(el('span',resource.username+'@'+resource.host+':'+(resource.port||22),'credential-target-address'));li.append(unassign);list.append(li);});form.append(list);}
  const status=el('p');const clean=()=>{const unchanged=form.dataset.initial===JSON.stringify(Array.from(form.querySelectorAll('input[name]')).map(input=>input.value));if(!unchanged)status.textContent=t('credentials.saveFirst','Save your password changes before changing host assignments.');return unchanged;};status.setAttribute('role','status');const save=el('button',t('common.save','Save'),'btn btn-primary');save.type='submit';save.disabled=state?.enabled===false;const actions=el('div',null,'credential-editor-actions');actions.append(save);form.append(status,actions);
  if(item.id){const remove=el('button',t('common.delete','Delete'),'btn btn-secondary');remove.type='button';const erasingAssigned=state?.enabled===false&&Boolean(item.uses?.length);remove.disabled=state?.enabled!==false&&Boolean(item.uses?.length);remove.onclick=async()=>{if(await question(erasingAssigned?t('credentials.deleteAssignedConfirm','Delete this password and remove its host assignments?'):t('credentials.deleteConfirm','Delete this unused password?'),{confirmation:true,acceptLabel:t('common.delete','Delete')})!==true)return;remove.disabled=true;try{await mutate('delete',{},item.id,active);onSaved();}catch(error){status.textContent=error.message;}finally{remove.disabled=false;}};actions.append(remove);}
  form.onsubmit=async event=>{event.preventDefault();if(form.dataset.assignmentsDirty==='true'){status.textContent=t('credentials.applyFirst','Apply or cancel your host assignment changes before saving password details.');return;}save.disabled=true;Object.values(fields).forEach(input=>input.disabled=true);const payload={name:fields.name.value.trim(),username:fields.username.value.trim()};if(fields.password.value)payload.password=fields.password.value;
   try{const knownIds=new Set((state?.credentials||[]).map(record=>record.id));const result=await mutate(item.id?'update':'create',payload,item.id,active);fields.password.value='';if(active())onSaved(item.id||result.credentials?.find(record=>!knownIds.has(record.id))?.id);}catch(error){if(error.name!=='AbortError')status.textContent=error.message;}finally{save.disabled=false;Object.values(fields).forEach(input=>input.disabled=false);}
  };container.append(form);form.dataset.initial=JSON.stringify(Array.from(form.querySelectorAll('input[name]')).map(input=>input.value));return form;
 }
 async function assignHosts(container,item,onSaved,current,canAssign){
  if(container.querySelector('.credential-targets'))return;
  const panel=el('div',null,'credential-targets'),form=container.closest('form');
  const status=el('p',t('credentials.loading','Loading passwords…'));status.setAttribute('role','status');panel.append(status);container.append(panel);
  try{
   const data=await load();if(!current()||!panel.isConnected)return;
   const targets=(data.profiles||[]).filter(resource=>resource.kind==='ssh'&&(!resource.auth_type||resource.auth_type==='password'));
   status.textContent='';if(!targets.length){status.textContent=t('credentials.noTargets','No password-authenticated hosts are available. Create or edit a host in Hosts.');return;}
   const baseline=new Map(targets.map(target=>[target.id,target.credential_id===item.id]));
   const selected=new Set(targets.filter(target=>baseline.get(target.id)).map(target=>target.id));
   const searchLabel=el('label',t('credentials.searchHosts','Search hosts'));const search=el('input');search.type='search';search.className='form-control';search.dataset.credentialTargetSearch='';searchLabel.append(search);
   const hint=el('p',t('credentials.assignmentChecklistHint','Select the hosts that should use this password. Unchecking a currently assigned host removes its assignment.'),'credential-hint');
   const summary=el('p',null,'credential-hint'),list=el('div',null,'credential-target-list');list.setAttribute('role','group');list.setAttribute('aria-label',t('credentials.assignmentsTitle','Assigned hosts'));
   const apply=el('button',t('credentials.applyChanges','Apply changes'),'btn btn-primary');apply.type='button';const cancel=el('button',t('common.cancel','Cancel'),'btn btn-secondary');cancel.type='button';
   let busy=false,completedTotal=0;const changes=()=>targets.filter(target=>selected.has(target.id)!==baseline.get(target.id));
   const update=()=>{const count=changes().length;form.dataset.assignmentsDirty=String(count>0);apply.disabled=busy||!count;summary.textContent=selected.size+' '+t('credentials.hostsSelected','hosts selected')+' · '+count+' '+t('credentials.pendingChanges','pending changes');};
   const render=()=>{list.replaceChildren();const query=search.value.toLowerCase();targets.filter(target=>(target.name+' '+target.username+'@'+target.host+':'+(target.port||22)).toLowerCase().includes(query)).forEach(target=>{
    const row=el('label',null,'credential-target-row'),check=el('input');check.type='checkbox';check.dataset.credentialTarget=target.id;check.checked=selected.has(target.id);check.disabled=busy;
    const copy=el('span'),name=el('strong',target.name),destination=el('span',target.username+'@'+target.host+':'+(target.port||22),'credential-target-address');copy.append(name,destination);
    const assigned=baseline.get(target.id)?t('credentials.currentAssignment','Currently assigned'):target.credential_id?(data.credentials.find(record=>record.id===target.credential_id)?.name||t('credentials.unavailableAssignment','Assigned password unavailable'))+' → '+item.name:t('credentials.notAssigned','Not assigned');copy.append(el('span',assigned,'credential-hint'));row.append(check,copy);check.onchange=()=>{if(check.checked)selected.add(target.id);else selected.delete(target.id);update();};list.append(row);
   });if(!list.children.length)list.append(el('p',t('credentials.noMatchingHosts','No hosts match your search.'),'credential-hint'));update();};
   search.oninput=render;cancel.onclick=async()=>{const host=form.parentElement,draft=Array.from(form.querySelectorAll('input[name]')).map(input=>[input.name,input.value]);const dirty=form.dataset.initial!==JSON.stringify(draft.map(([,value])=>value));form.dataset.assignmentsDirty='false';panel.remove();if(completedTotal){await onSaved(item.id);if(dirty&&host?.isConnected&&host.dataset.credentialId===item.id){for(const [name,value]of draft){const input=host.querySelector('input[name="'+name+'"]');if(input)input.value=value;}}}};panel.prepend(searchLabel,hint,summary,list);const actions=el('div',null,'credential-picker-controls');actions.append(apply,cancel);panel.append(actions);
   apply.onclick=async()=>{
    if(busy||!canAssign())return;const pending=changes();busy=true;cancel.disabled=true;const locked=Array.from(form.querySelectorAll('button,input[name]')).filter(control=>!panel.contains(control)).map(control=>[control,control.disabled]);locked.forEach(([control])=>control.disabled=true);render();let completed=0;
    try{
     const replacements=pending.filter(target=>selected.has(target.id)&&target.credential_id&&target.credential_id!==item.id).map(resource=>({resource,oldName:data.credentials.find(record=>record.id===resource.credential_id)?.name||t('credentials.unavailableAssignment','Assigned password unavailable'),newName:item.name}));
     if(!await confirmReplacements(replacements))return;
     for(const target of pending){const valid=()=>current()&&canAssign()&&panel.isConnected;const result=await mutate('assign',{resource_id:target.id,credential_id:selected.has(target.id)?item.id:null,confirm_target:true,target},null,valid,true);baseline.set(target.id,selected.has(target.id));const refreshed=result.profiles?.find(resource=>resource.id===target.id);if(refreshed)Object.assign(target,refreshed);completed++;completedTotal++;}
     if(current()){form.dataset.assignmentsDirty='false';onSaved(item.id);}
    }catch(error){if(current())status.textContent=completed+' / '+pending.length+' '+t('credentials.changesApplied','changes applied')+'. '+(error.name==='AbortError'?t('credentials.assignmentInterrupted','Assignment stopped. Review the remaining changes.'):error.message);}
    finally{busy=false;cancel.disabled=false;locked.forEach(([control,disabled])=>control.disabled=disabled);if(panel.isConnected)render();}
   };render();search.focus();
  }catch(error){if(current())status.textContent=error.message;}
 }
 async function mount(selectedId=null){
  const view=document.getElementById('credentialManagementView');if(!view)return;const list=view.querySelector('[data-credential-list]');const detail=view.querySelector('[data-credential-detail]');const search=view.querySelector('[data-credential-search]');const notice=view.querySelector('[role="status"]');
  try{const state=await load();notice.textContent=state.enabled?'':t('credentials.disabled','Password storage is disabled by the administrator.');view.querySelector('[data-credential-new]').disabled=!state.enabled;
   if(!state.enabled){const help=el('a','Wiki','btn btn-secondary');help.href='https://github.com/bifrost0x/webssh/wiki/Profiles-Jump-Hosts-and-Commands';help.target='_blank';help.rel='noopener noreferrer';notice.append(document.createTextNode(' '),help);detail.replaceChildren();list.replaceChildren();view.querySelector('[data-credential-legacy]').hidden=true;(state.credentials||[]).forEach(item=>{const row=el('div',null,'native-credential-row');row.append(el('strong',item.name));const remove=el('button',t('common.delete','Delete'),'btn btn-secondary');remove.type='button';remove.onclick=async()=>{const assigned=Boolean(item.uses?.length);if(await question(assigned?t('credentials.deleteAssignedConfirm','Delete this password and remove its host assignments?'):t('credentials.deleteConfirm','Delete this unused password?'),{confirmation:true,acceptLabel:t('common.delete','Delete')})!==true)return;remove.disabled=true;try{await mutate('delete',{},item.id);await mount();}catch(error){notice.textContent=error.message;remove.disabled=false;}};row.append(remove);list.append(row);});return;}
   const saved=id=>{const chosen=id||detail.dataset.credentialId;detail.replaceChildren();return mount(chosen);};const discard=async()=>{const form=detail.querySelector('form');if(!form||(form.dataset.assignmentsDirty!=='true'&&form.dataset.initial===JSON.stringify(Array.from(form.querySelectorAll('input[name]')).map(input=>input.value))))return true;return await question(t('editor.unsavedConfirm','Discard unsaved changes?'),{confirmation:true})===true;};
   const back=el('button',t('common.backToList','Back to list'),'btn btn-secondary credential-back');back.type='button';back.onclick=async()=>{if(!await discard())return;detail.hidden=true;detail.replaceChildren();view.classList.remove('has-credential-detail');search.focus();};if(!view.querySelector('.credential-back'))view.querySelector('.native-credential-toolbar').prepend(back);
   const render=()=>{list.replaceChildren();const records=(state.credentials||[]).filter(item=>`${item.name} ${item.username}`.toLowerCase().includes(search.value.toLowerCase()));if(!records.length)list.append(el('p',t('credentials.empty','No passwords found.')));records.forEach(item=>{const button=el('button',null,'native-credential-row');button.type='button';button.setAttribute('aria-pressed',String(item.id===(detail.dataset.credentialId||selectedId)));button.append(el('strong',item.name),el('span',`${item.username||''} · ${item.uses?.length||0} ${t('credentials.assignments','assignments')}`));button.onclick=async()=>{if(!await discard())return;detail.dataset.credentialId=item.id;list.querySelectorAll('button').forEach(row=>row.setAttribute('aria-pressed',String(row===button)));editor(detail,item,saved);detail.hidden=false;view.classList.add('has-credential-detail');detail.querySelector('input')?.focus();};list.append(button);});};search.oninput=render;view.querySelector('[data-credential-new]').onclick=async()=>{if(!await discard())return;detail.dataset.credentialId='';editor(detail,{},saved);detail.hidden=false;view.classList.add('has-credential-detail');detail.querySelector('input')?.focus();};render();if(selectedId){const selected=state.credentials?.find(item=>item.id===selectedId);if(selected){detail.dataset.credentialId=selected.id;editor(detail,selected,saved);detail.hidden=false;view.classList.add('has-credential-detail');}}if(!detail.children.length){detail.hidden=false;view.classList.remove('has-credential-detail');detail.append(el('div',t('credentials.selectHint','Select a password to view its details and host assignments.'),'credential-empty-detail'));}
   const legacy=view.querySelector('[data-credential-legacy]');legacy.hidden=!state.legacy_vault;legacy.onclick=async()=>{if(!await discard())return;const passphrase=await question(t('credentials.legacyPassphrase','Import old vault: enter its original passphrase'),{secret:true,heading:t('credentials.importLegacy','Import existing vault')});if(passphrase===null)return;legacy.disabled=true;try{await mutate('import',{passphrase});await mount();}catch(error){notice.textContent=error.message;}finally{legacy.disabled=false;}};
  }catch(error){notice.textContent=error.message;}
 }
 async function pick(resourceId,target,isCurrent=()=>true){
  const data=await load();if(!isCurrent())return null;if(!data.enabled)throw new Error(t('credentials.disabled','Password storage is disabled by the administrator.'));
  return new Promise(resolve=>{
   const dialog=el('dialog',null,'credential-picker-dialog');const title=el('h2',t('credentials.use','Use saved password'));const destination=el('p',`${target.username || ''}@${target.host || ''}${target.port ? ':' + target.port : ''}${target.share ? '/' + target.share : ''}${target.domain ? ' · ' + target.domain : ''}`);const search=el('input');search.type='search';search.className='form-control';search.placeholder=t('credentials.search','Search passwords');search.setAttribute('aria-label',search.placeholder);const list=el('div',null,'native-credential-list');const detail=el('div');const status=el('p');status.setAttribute('role','status');const actions=el('div',null,'credential-picker-controls');const create=el('button',t('credentials.new','New password'),'btn btn-secondary');create.type='button';const cancel=el('button',t('common.cancel','Cancel'),'btn btn-secondary');cancel.type='button';actions.append(create,cancel);dialog.append(title,destination,search,list,detail,status,actions);document.body.append(dialog);let selected=null,choosing=false;
   const current=()=>dialog.isConnected&&dialog.open&&isCurrent();
   function render(){list.replaceChildren();(state.credentials||[]).filter(item=>`${item.name} ${item.username}`.toLowerCase().includes(search.value.toLowerCase())).forEach(item=>{const button=el('button',item.name,'native-credential-row');button.type='button';button.onclick=async()=>{if(!current()||choosing)return;choosing=true;button.disabled=true;try{if(resourceId){await mutate('assign',{resource_id:resourceId,credential_id:item.id,confirm_target:true,target},null,current);if(current()){selected={id:resourceId};dialog.close();}}else{const result=await authorizeTarget(item.id,target,current);if(current()){selected={id:item.id,token:result.credential_target_token};dialog.close();}}}catch(error){if(error.name!=='AbortError')status.textContent=error.message;}finally{choosing=false;button.disabled=false;}};list.append(button);});if(!list.children.length)list.append(el('p',t('credentials.empty','No passwords found.')));}
   search.oninput=render;create.onclick=()=>editor(detail,{},()=>{detail.replaceChildren();render();},current);cancel.onclick=()=>dialog.close();dialog.onclose=()=>{dialog.querySelectorAll('input[type="password"]').forEach(input=>input.value='');dialog.remove();resolve(selected);};dialog.addEventListener('keydown',event=>event.stopPropagation());dialog.showModal();render();search.focus();
  });
 }
 function installHostEditor() {
  const auth=document.getElementById('profileEditorAuthType');if(!auth)return;
  const section=el('section',null,'native-host-credentials');const label=el('label',t('credentials.title','Passwords'));const select=el('select');select.id='profileEditorCredential';select.className='form-control';label.append(select);const inline=el('div');inline.hidden=true;
  const nameLabel=el('label',t('credentials.name','Name'));const name=el('input');name.id='profileEditorCredentialName';name.className='form-control';name.maxLength=120;nameLabel.append(name);
  const passwordLabel=el('label',t('credentials.password','Password'));const password=el('input');password.id='profileEditorCredentialPassword';password.type='password';password.autocomplete='new-password';password.className='form-control';passwordLabel.append(password);inline.append(nameLabel,passwordLabel);section.append(label,inline);auth.closest('.form-group').after(section);
  let enabled=false;const sync=()=>{section.hidden=auth.value!=='password'||(!enabled&&!['true','error','unavailable'].includes(select.dataset.loading));inline.hidden=select.value!=='__new';if(!inline.hidden&&!name.value)name.value=document.getElementById('profileEditorName').value;};auth.addEventListener('change',sync);select.onchange=()=>{sync();const selected=state?.credentials?.find(item=>item.id===select.value);const user=document.getElementById('profileEditorUsername');if(selected?.username&&!user.value)user.value=selected.username;};
  let generation=0;
  const status=el('p');status.setAttribute('role','status');const retry=el('button',t('credentials.retry','Reload passwords'),'btn btn-secondary btn-sm');retry.type='button';retry.hidden=true;section.append(status,retry);
  const refresh=async()=>{
   const request=++generation,profileId=window.ProfileManager?.editingProfileId;const valid=()=>request===generation&&profileId===window.ProfileManager?.editingProfileId;
   password.value='';name.value='';label.hidden=false;select.replaceChildren();select.disabled=true;select.dataset.loading='true';select.dataset.assigned='';select.dataset.confirmRequired='false';section.hidden=auth.value!=='password';status.textContent=t('credentials.loading','Loading passwords…');retry.hidden=true;
   const baseline=window.ProfileManager?.editorSnapshot?.();
   try{const data=await load();if(!valid())return;enabled=data.enabled===true;const manual=el('option',t('credentials.manual','Enter manually'));manual.value='';select.append(manual);
    if(data.enabled){(data.credentials||[]).forEach(item=>{const option=el('option',item.name);option.value=item.id;select.append(option);});const create=el('option',t('credentials.new','New password'));create.value='__new';select.append(create);}
    const profile=data.profiles?.find(item=>String(item.id)===String(profileId));const assigned=profile?.credential_id||'';
    if(assigned&&!data.credentials?.some(item=>item.id===assigned)){const missing=el('option',t('credentials.missing','Assigned password unavailable'));missing.value=assigned;missing.disabled=true;select.append(missing);}
    const unchanged=baseline===window.ProfileManager?.editorSnapshot?.();select.value=assigned;select.dataset.assigned=assigned;select.dataset.confirmRequired=String(Boolean(assigned&&profile?.credential_status!=='ready'));select.dataset.loading='false';select.disabled=false;status.textContent='';sync();if(unchanged&&window.ProfileManager)window.ProfileManager.editorBaseline=window.ProfileManager.editorSnapshot();
   }catch(error){
    if(!valid())return;
    if(error.code==='https_required'){
     // The server rejects credential access over HTTP. Host metadata remains
     // editable; saving it must not create, replace or remove an assignment.
     enabled=false;select.dataset.loading='unavailable';
     const manual=el('option',t('credentials.manual','Enter manually'));manual.value='';select.append(manual);
     label.hidden=true;inline.hidden=true;status.textContent=error.message;retry.hidden=true;
     if(baseline===window.ProfileManager?.editorSnapshot?.()&&window.ProfileManager)window.ProfileManager.editorBaseline=window.ProfileManager.editorSnapshot();
     return;
    }
    select.dataset.loading='error';status.textContent=t('credentials.loadFailed','Passwords could not be loaded. Reload before saving this host.');retry.hidden=false;
   }
  };
  retry.onclick=refresh;window.addEventListener('webssh:profile-editor',refresh);

 }
 function installInlineCreate(formId,prefix){
  const form=document.getElementById(formId);if(!form)return;
  const section=el('section',null,'native-host-credentials');const label=el('label');const enable=el('input');enable.type='checkbox';enable.id=prefix+'SavePassword';label.append(enable,document.createTextNode(t('credentials.new','New password')));const fields=el('div');fields.hidden=true;
  for(const [key,text,type]of [['Name',t('credentials.name','Name'),'text'],['Password',t('credentials.password','Password'),'password']]){const row=el('label',text);const input=el('input');input.type=type;input.id=prefix+key;input.className='form-control';input.autocomplete=type==='password'?'new-password':'off';row.append(input);fields.append(row);}enable.onchange=()=>fields.hidden=!enable.checked;form.addEventListener('reset',()=>{fields.hidden=true;fields.querySelector('input[type=password]').value='';});const existingLabel=el('label',t('credentials.use','Use saved password'));const existing=el('select');existing.id=prefix+'Existing';existing.className='form-control';const manual=el('option',t('credentials.manual','Enter manually'));manual.value='';existing.append(manual);existingLabel.append(existing);existing.onfocus=async()=>{try{const data=await load();const selected=existing.value;existing.replaceChildren(manual);(data.credentials||[]).forEach(item=>{const option=el('option',item.name);option.value=item.id;existing.append(option);});existing.value=selected;}catch{}};existing.onchange=()=>{if(existing.value){enable.checked=false;fields.hidden=true;const item=state?.credentials?.find(record=>record.id===existing.value);const user=document.getElementById(prefix==='jhCredential'?'jhUsernameInput':'smbSourceUsername');if(user&&!user.value&&item?.username)user.value=item.username;}};enable.addEventListener('change',()=>{if(enable.checked)existing.value='';});section.append(existingLabel,label,fields);form.querySelector('.form-actions')?.before(section);if(!section.isConnected)form.append(section);load().then(data=>{section.hidden=!data.enabled;(data.credentials||[]).forEach(item=>{const option=el('option',item.name);option.value=item.id;existing.append(option);});}).catch(()=>section.hidden=true);const modal=form.closest('.modal');if(modal)new MutationObserver(()=>{if(!modal.classList.contains('show'))fields.querySelector('input[type=password]').value='';}).observe(modal,{attributes:true,attributeFilter:['class']});
 }
 function inlineIdentity(prefix){return JSON.stringify(['Existing','SavePassword','Name','Password'].map(suffix=>{const input=document.getElementById(prefix+suffix);return input?.type==='checkbox'?input.checked:input?.value;}));}
 function inlineDraft(prefix){const existing=document.getElementById(prefix+'Existing');const selected=existing?.value;if(selected)return {credential_id:selected};if(!document.getElementById(prefix+'SavePassword')?.checked)return existing?.dataset.assigned?{credential_id:null}:null;const name=document.getElementById(prefix+'Name').value.trim(),password=document.getElementById(prefix+'Password').value;if(!name||!password)throw new Error(t('credentials.required','Enter a password name and password.'));return {name,password};}
 async function refreshInline(prefix,resourceId){
  const select=document.getElementById(prefix+'Existing');if(!select)return;
  select.value='';select.dataset.assigned='';select.dataset.resource=resourceId||'';document.getElementById(prefix+'SavePassword').checked=false;document.getElementById(prefix+'Password').value='';document.getElementById(prefix+'Name').value='';document.getElementById(prefix+'Password').parentElement.parentElement.hidden=true;
  const form=select.closest('form'),snapshot=JSON.stringify(Array.from(form.querySelectorAll('input,select')).map(input=>input.type==='checkbox'||input.type==='radio'?input.checked:input.value));
  try{const data=await load();select.closest('.native-host-credentials').hidden=!data.enabled;if(select.dataset.resource!==(resourceId||'')||snapshot!==JSON.stringify(Array.from(form.querySelectorAll('input,select')).map(input=>input.type==='checkbox'||input.type==='radio'?input.checked:input.value)))return;const resource=data.profiles.find(item=>item.id===resourceId);const manual=el('option',t('credentials.manual','Enter manually'));manual.value='';select.replaceChildren(manual);data.credentials.forEach(item=>{const option=el('option',item.name);option.value=item.id;select.append(option);});select.value=resource?.credential_id||'';select.dataset.assigned=resource?.credential_id||'';select.dataset.confirmRequired=String(Boolean(resource?.credential_id&&resource?.credential_status!=='ready'));if(prefix==='jhCredential'&&window.JumpHostManager?.editingId===(resourceId?resourceId.slice(5):null))window.JumpHostManager.baseline=window.JumpHostManager.draft();}catch{}
 }
 async function confirmTargetReuse(target){return await question(t('credentials.confirmTarget','Reuse this saved password for the changed destination?')+' '+target.username+'@'+target.host+':'+target.port+(target.share?'/'+target.share:'')+(target.domain?' · '+target.domain:''),{confirmation:true})===true;}
 window.NativeCredentials={api,authorizeTarget,mutate,load,mount,pick,editor,inlineDraft,inlineIdentity,confirmTargetReuse,refreshInline};
 document.addEventListener('DOMContentLoaded',()=>{installInlineCreate('jumpHostForm','jhCredential');installInlineCreate('smbSourceForm','smbCredential');});
 document.addEventListener('DOMContentLoaded',installHostEditor);
}());
