const {test,expect}=require('playwright/test');
const {login}=require('./helpers');
for(const width of [390,1440,3440]) test(`connection resources share list-first layout at ${width}`,async({page},info)=>{
 await page.setViewportSize({width,height:900});await login(page);
 await page.route('**/api/credentials/state',route=>route.fulfill({json:{enabled:true,credentials:[{id:'layout-password',name:'Server password',username:'operator',version:1,uses:[]}],profiles:[],legacy_vault:false}}));
 const errors=[];page.on('pageerror',error=>errors.push(error.message));
 for(const [kind,id,newId,field] of [['jump-hosts','jumpHostManagementModal','jumpResourceNew','jhNameInput'],['keys','keyManagementModal','keyResourceNew','keyNameInput'],['passwords','credentialManagementView',null,null]]){
  await page.evaluate(kind=>window.openConnectionAssetManager(kind),kind);
  const view=page.locator('#'+id);await expect(view).toBeVisible();
  if(field)await expect(page.locator('#'+field)).toBeHidden();
  for(const theme of ['glass','retro','solar','paper','noir','arctic-ice','rose-gold','cyberpunk-neon','emerald-matrix','obsidian','werkbank']){
   await page.evaluate(theme=>document.body.dataset.theme=theme,theme);
   expect(await view.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
  }
  await page.screenshot({path:info.outputPath(kind+'-list.png'),animations:'disabled'});
  if(newId){await page.locator('#'+newId).click();await expect(page.locator('#'+field)).toBeVisible();}
  else {await view.locator('[data-credential-new]').click();await expect(view.locator('[data-credential-detail] input').first()).toBeVisible();}
  expect(await view.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
  for(const theme of ['glass','retro','solar','paper','noir','arctic-ice','rose-gold','cyberpunk-neon','emerald-matrix','obsidian','werkbank']){
   await page.evaluate(theme=>document.body.dataset.theme=theme,theme);
   expect(await view.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
  }
  if(width>1000){const editor=await view.locator(kind==='passwords'?'[data-credential-detail]':'.host-resource-editor').boundingBox();expect(editor.width).toBeGreaterThan(width===3440?1100:800);}
  await page.screenshot({path:info.outputPath(kind+'-editor.png'),animations:'disabled'});
 }
 expect(errors).toEqual([]);
});
