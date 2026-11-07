const {test,expect}=require('playwright/test');const {login}=require('./helpers');
test('command set creation uses the shared management width on wide screens',async({page},info)=>{
 await login(page,'e2e_user');await page.evaluate(()=>window.CommandSetManager.openBuilder());
 for(const width of [390,1440,3440,3840]){
  await page.setViewportSize({width,height:1000});
  const form=await page.locator('#commandSetForm').boundingBox(),header=await page.locator('.header-content').boundingBox();
  if(width>=1440)expect(form.width).toBeGreaterThan(header.width*.9);
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  await page.screenshot({path:info.outputPath('command-builder-'+width+'.png'),animations:'disabled'});
 }
});
