const {test,expect}=require('playwright/test');
const {login}=require('./helpers');
for(const width of [390,1280]){
 for(const kind of ['new','existing']){
  test(`host ${kind} draft survives workspace navigation at ${width}px`,async({page})=>{
   await page.setViewportSize({width,height:900});
   await login(page);
   const navigate=async view=>{
    if(width<768) await page.locator(`.mobile-dock-item[data-mobile-view="${view}"]`).click();
    else await page.locator(view==='hosts'?'#manageProfilesBtn':'#commandLibraryBtn').click();
   };
   await navigate('hosts');
   if(kind==='new') await page.locator('#newProfileBtn').click();
   else await page.getByRole('button',{name:'Usable key',exact:true}).click();
   const name=page.locator('#profileEditorName');
   await name.fill('Unsaved navigation draft');
   await navigate('commands');
   await expect(page.locator('body')).toHaveAttribute('data-primary-workspace','commands');
   await navigate('hosts');
   await expect(name).toBeVisible();
   await expect(name).toHaveValue('Unsaved navigation draft');
  });
 }
}
