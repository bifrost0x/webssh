const {test,expect}=require('playwright/test');
const crypto=require('node:crypto');
const {login}=require('./helpers');

// Names of jump hosts, SOCKS5 proxies and SSH keys are unique per user from
// 3.4 (U72): a name in use, in any case and with surrounding spaces, is
// refused at the name field and nothing is stored. Go only (go_only in
// go-suite.json): the default Python run leaves this file out. Run against
// Python with another server command, the Python release stores the second
// record, so the tests are expected to fail and remove what it stored.
const goBackend=page=>page.evaluate(()=>Boolean(window.WebSSHRealtimeAreas));
const message='This name is already in use. Choose another name.';

// Removes the records of list whose name matches and whose id is not in
// keep, with the delete event of their kind.
async function removeNew(page,{list,event,idField},name,keep){
 await page.evaluate(async ({list,event,idField,name,keep})=>{
  const key=value=>String(value||'').trim().toLowerCase();
  const records=list.split('.').reduce((value,part)=>value?.[part],window)||[];
  for(const record of records.filter(item=>key(item.name)===key(name)&&!keep.includes(item.id))){
   await new Promise(resolve=>window.socket.emit(event,{[idField]:record.id},resolve));
  }
 },{list,event,idField,name,keep});
}

async function ids(page,list){
 return page.evaluate(list=>(list.split('.').reduce((value,part)=>value?.[part],window)||[]).map(item=>item.id),list);
}

const resources=[
 {kind:'jump host',asset:'jump-hosts',newButton:'#jumpResourceNew',field:'#jhNameInput',taken:'  e2e KEY jump host ',
  list:'JumpHostManager.jumpHosts',event:'delete_jump_host',idField:'jump_host_id',
  fill:async page=>{
   await page.locator('#jhHostInput').fill('unique-jump.example.test');
   await page.locator('#jhPortInput').fill('22');
   await page.locator('#jhUsernameInput').fill('unique');
  },submit:'#jumpHostForm button[type="submit"]'},
 {kind:'SOCKS5 proxy',asset:'socks-proxies',newButton:'#socksResourceNew',field:'#spNameInput',taken:'E2E NONE socks proxy',
  list:'SocksProxyManager.socksProxies',event:'delete_socks_proxy',idField:'socks_proxy_id',
  fill:async page=>{
   await page.locator('#spHostInput').fill('unique-socks.example.test');
   await page.locator('#spPortInput').fill('1080');
  },submit:'#socksProxyForm button[type="submit"]'},
];

for(const resource of resources){
 test(`a ${resource.kind} name in use is refused at the name field`,async({page})=>{
  await page.setViewportSize({width:1440,height:900});
  await login(page);
  test.fail(!(await goBackend(page)),'the Python release allows duplicate names');
  await page.evaluate(asset=>window.openConnectionAssetManager(asset),resource.asset);
  const before=await ids(page,resource.list);
  try {
   await page.locator(resource.newButton).click();
   await page.locator(resource.field).fill(resource.taken);
   await resource.fill(page);
   await page.locator(resource.submit).click();
   const hint=page.locator(`${resource.field}Error`);
   await expect(hint).toHaveText(message);
   await expect(page.locator(resource.field)).toHaveAttribute('aria-invalid','true');
   await expect(page.locator(resource.field)).toBeFocused();
   await expect(page.locator(resource.field)).toHaveValue(resource.taken);
   await expect(page.locator(resource.submit)).toBeEnabled();
   expect(await ids(page,resource.list)).toEqual(before);
   // Typing clears the hint.
   await page.locator(resource.field).fill(`${resource.taken.trim()} 2`);
   await expect(hint).toBeHidden();
  } finally {
   await removeNew(page,resource,resource.taken,before);
  }
 });
}

test('an SSH key name in use is refused at the name field before any confirmation',async({page})=>{
 await page.setViewportSize({width:1440,height:900});
 await login(page);
 test.fail(!(await goBackend(page)),'the Python release allows duplicate names');
 await page.evaluate(()=>window.openConnectionAssetManager('keys'));
 const before=await ids(page,'ProfileManager.keys');
 const {privateKey}=crypto.generateKeyPairSync('ed25519');
 const pem=privateKey.export({type:'pkcs8',format:'pem'});
 try {
  const stepUps=[];
  page.on('request',request=>{if(request.url().includes('/api/account/step-up/'))stepUps.push(request.url());});
  await page.locator('#keyResourceNew').click();
  await page.locator('#keyNameInput').fill(' e2e USABLE key');
  await page.locator('#keyContentInput').fill(pem);
  await page.locator('#keyUploadForm button[type="submit"]').click();
  await expect(page.locator('#keyNameInputError')).toHaveText(message);
  await expect(page.locator('#keyNameInput')).toBeFocused();
  // The name is refused before the step-up, so no confirmation starts.
  expect(stepUps).toEqual([]);
  await expect(page.locator('#keyUploadForm button[type="submit"]')).toBeEnabled();
  expect(await ids(page,'ProfileManager.keys')).toEqual(before);
 } finally {
  await removeNew(page,{list:'ProfileManager.keys',event:'delete_key',idField:'key_id'},' e2e USABLE key',before);
 }
});
