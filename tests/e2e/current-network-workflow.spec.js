const {test,expect}=require('playwright/test');
const {login,assertNoExternalRequests}=require('./helpers');
for(const width of [360,870,1440]) test(`current network arrangement remains operable at ${width}px`,async({page},testInfo)=>{
 await page.setViewportSize({width,height:740});
 await login(page,'e2e_admin',{workspace:false});
 await page.evaluate(()=>ProfileManager.setProfiles(['Alpha','Beta','Gamma'].map(group=>({id:group,name:group+' host',group,host:'example.test'}))));
 await page.locator('#overviewArrangeGroups').click();
 const groups=page.locator('#overviewHosts .overview-list-group');
 await expect(groups).toHaveCount(3);
 const order=()=>groups.evaluateAll(rows=>rows.map(row=>row.dataset.overviewGroup));
 await expect.poll(order).toEqual(['Alpha','Beta','Gamma']);
 await page.locator('#overviewSortGroupsDesc').click();
 await expect.poll(order).toEqual(['Gamma','Beta','Alpha']);
 const position=groups.last().locator('input');
 await position.fill('1');await position.press('Enter');
 await expect.poll(order).toEqual(['Alpha','Gamma','Beta']);
 await page.locator('#overviewArrangeGroups').click();
 await expect(page.locator('.overview-group-controls')).toHaveCount(0);
 if(width===360){
  await page.locator('.mobile-dock-item[data-mobile-view="hosts"]').click();
  await expect(page.locator('#profileManagementModal .management-resource-title')).toBeHidden();
  await expect(page.locator('#profileManagementModal [data-connection-asset="keys"]')).toBeInViewport();
  await page.screenshot({path:testInfo.outputPath('hosts-short.png'),animations:'disabled'});
 }
 await assertNoExternalRequests(page);
});
