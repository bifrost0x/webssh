const {test,expect}=require('playwright/test');
const {login,waitForInventory}=require('./helpers');
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

test('an unsaved role choice asks before it is discarded and a saved one shows on the card',async({page})=>{
 await page.setViewportSize({width:1280,height:900});
 await login(page);
 await page.locator('#manageProfilesBtn').click();
 await page.getByRole('button',{name:'Usable key',exact:true}).click();
 await page.locator('#profileAdvancedSettingsCard > summary').click();
 const role=page.locator('#profileEditorRole');
 await expect(role).toHaveValue('auto');
 await role.selectOption('backup');
 await page.locator('#cancelProfileEditorBtn').click();
 const dialog=page.locator('.command-set-confirm-dialog');
 await expect(dialog).toBeVisible();
 await dialog.getByRole('button',{name:'Keep editing',exact:true}).click();
 await expect(role).toHaveValue('backup');
 await page.locator('#profileEditorForm button[type="submit"]').first().click();
 await expect(page.locator('#profileEditorView')).toBeHidden();
 await page.goto('/');
 await waitForInventory(page);
 const card=page.locator('#overviewHostList .od-host',{hasText:'Usable key'}).first();
 await expect(card).toHaveAttribute('data-role','backup');
 await expect(card.locator('.od-role')).toHaveText(/Backup/);
 await card.locator('.od-host-profile > summary').click();
 await expect(card.locator('.od-host-profile dd').filter({hasText:/Backup/})).toHaveText(/Backup.*manual/);
});
