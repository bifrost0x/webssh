const {test,expect}=require('playwright/test');const {login}=require('./helpers');
test('overview keeps the unavailable automation status through language changes until a successful refresh',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 await page.route('**/api/automation/state',r=>r.fulfill({json:{enabled:true,runbooks:[],profiles:[]}}));await page.route('**/api/automation/schedules',r=>r.fulfill({json:{schedules:[]}}));
 let offline=true;await page.route('**/api/automation/runs',r=>r.fulfill(offline?{status:503,json:{code:'unavailable'}}:{json:{runs:[{id:'old',name:'Last confirmed result',status:'succeeded',created_at:new Date().toISOString(),targets:[]}]}}));
 await page.goto('/');await expect(page.locator('#odAutomation')).toBeVisible();await expect(page.locator('#odNextRun')).toHaveText('Automation data is unavailable right now.',{timeout:10000});
 await page.evaluate(()=>window.i18n.setLanguage('de'));await expect(page.locator('#odNextRun')).toHaveText('Automatisierungsdaten sind gerade nicht verfügbar.');
 offline=false;await expect(page.locator('#odNextRun')).not.toContainText('nicht verfügbar',{timeout:10000});await expect(page.locator('#odActivity')).toContainText('Last confirmed result');
});
test('overview hides automation as soon as an administrator disables it', async ({page}) => {
    await login(page, 'e2e_admin', {workspace: false});
    let disabled = false;
    const run = {id: 'r1', name: 'Nightly', status: 'succeeded', created_at: new Date().toISOString(), targets: []};
    await page.route('**/api/automation/state', route => route.fulfill(disabled ? {status: 403, json: {code: 'disabled'}} : {json: {enabled: true, runbooks: [], profiles: []}}));
    await page.route('**/api/automation/runs', route => route.fulfill(disabled ? {status: 403, json: {code: 'disabled'}} : {json: {runs: [run]}}));
    await page.route('**/api/automation/schedules', route => route.fulfill(disabled ? {status: 403, json: {code: 'disabled'}} : {json: {schedules: []}}));
    await page.goto('/');
    await expect(page.locator('#odAutomation')).toBeVisible();
    disabled = true;
    await expect(page.locator('#odAutomation')).toBeHidden({timeout: 10000});
    await expect(page.locator('#odActivity')).not.toContainText('Nightly');
});
