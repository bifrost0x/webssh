const {test,expect}=require('playwright/test');
const {login,assertNoExternalRequests}=require('./helpers');
test('every saved host remains present and named in the launcher after platform icons render',async({page})=>{
 const errors=[];page.on('pageerror',error=>errors.push(error.message));
 await login(page);
 const profiles=await page.evaluate(()=>ProfileManager.profiles.map(({id,name})=>({id,name})));
 const cards=page.locator('.profile-launcher-card');
 await expect(cards).toHaveCount(profiles.length);
 const ids=await cards.evaluateAll(rows=>rows.map(row=>row.dataset.profileId));
 expect([...ids].sort()).toEqual(profiles.map(p=>p.id).sort());
 for(let index=0;index<ids.length;index++){
  const name=profiles.find(p=>p.id===ids[index]).name;
  await expect(cards.nth(index)).toHaveAccessibleName(new RegExp('^'+name.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+','));
 }
 expect(errors).toEqual([]);await assertNoExternalRequests(page);
});
