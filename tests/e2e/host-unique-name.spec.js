const {test,expect}=require('playwright/test');
const {login,openProfileManagement}=require('./helpers');

// The Go server loads the realtime shim; the Python release uses Socket.IO.
const goBackend=page=>page.evaluate(()=>Boolean(window.WebSSHRealtimeAreas));

async function openNewHost(page){
 await page.setViewportSize({width:1280,height:900});
 await login(page);
 await openProfileManagement(page);
 await page.locator('#newProfileBtn').click();
 await expect(page.locator('#profileEditorView')).toBeVisible();
}

// The specs share the seed account: hosts made here are removed again,
// and their names start with no seeded name.
async function removeHosts(page,name){
 await page.evaluate(async name=>{
  for(const profile of window.ProfileManager.profiles.filter(item=>item.name===name)){
   await new Promise(resolve=>window.socket.emit('delete_profile',{profile_id:profile.id},resolve));
  }
 },name);
 await expect.poll(()=>page.evaluate(name=>window.ProfileManager.profiles.filter(item=>item.name===name).length,name)).toBe(0);
}

// Removes the hosts of this name (any case) that are not in ids: the
// duplicate a backend without the name rule stored.
async function removeDuplicates(page,name,ids){
 await page.evaluate(async ({folded,keep})=>{
  for(const profile of window.ProfileManager.profiles.filter(item=>item.name.trim().toLowerCase()===folded&&!keep.includes(item.id))){
   await new Promise(resolve=>window.socket.emit('delete_profile',{profile_id:profile.id},resolve));
  }
 },{folded:name.trim().toLowerCase(),keep:ids});
}

async function fillHost(page,name){
 await page.locator('#profileEditorName').fill(name);
 await page.locator('#profileEditorHost').fill('unique-name.example.test');
 await page.locator('#profileEditorUsername').fill('unique');
}

test('rapid clicks on Save and Save & connect store the host once',async({page})=>{
 await openNewHost(page);
 const name=`T2 rapid save ${Date.now()}`;
 await fillHost(page,name);
 // Clicks in one task: the second and later ones arrive before any answer.
 await page.evaluate(()=>{
  const [save,connect]=document.querySelectorAll('#profileEditorForm button[type="submit"]');
  for(let i=0;i<4;i+=1) save.click();
  connect.click();
 });
 await expect(page.locator('#profileEditorView')).toBeHidden();
 await page.reload();
 await openProfileManagement(page);
 await expect(page.locator('#profileManagementView').getByText(name,{exact:true})).toHaveCount(1);
 expect(await page.evaluate(n=>window.ProfileManager.profiles.filter(p=>p.name===n).length,name)).toBe(1);
 await removeHosts(page,name);
});

test('a name another saved host has is refused at the name field',async({page})=>{
 await openNewHost(page);
 // Intended change in 3.4: the Python release stored a second host with
 // the same name.
 test.fail(!(await goBackend(page)),'the Python release allows duplicate host names');
 const before=await page.evaluate(()=>window.ProfileManager.profiles.length);
 const seeded=await page.evaluate(()=>window.ProfileManager.profiles.map(profile=>profile.id));
 try {
  await fillHost(page,'  USABLE KEY ');
  await page.locator('#profileEditorForm button[type="submit"]').first().click();
  const hint=page.locator('#profileEditorNameError');
  await expect(hint).toBeVisible();
  await expect(hint).toHaveText('A saved host with this name already exists. Choose another name.');
  await expect(page.locator('#profileEditorName')).toHaveAttribute('aria-invalid','true');
  await expect(page.locator('#profileEditorName')).toBeFocused();
  await expect(page.locator('#profileEditorView')).toBeVisible();
  await expect(page.locator('#profileEditorName')).toHaveValue('  USABLE KEY ');
  await expect(page.locator('#profileEditorForm button[type="submit"]').first()).toBeEnabled();
  expect(await page.evaluate(()=>window.ProfileManager.profiles.length)).toBe(before);
  // Typing clears the hint; a free name saves.
  const free=`T2 free name ${Date.now()}`;
  await page.locator('#profileEditorName').fill(free);
  await expect(hint).toBeHidden();
  await page.locator('#profileEditorForm button[type="submit"]').first().click();
  await expect(page.locator('#profileEditorView')).toBeHidden();
  await removeHosts(page,free);
 } finally {
  // Python stores the duplicate; the shared seed account must not keep it.
  await removeDuplicates(page,'usable key',seeded);
 }
});
