const {test,expect}=require('playwright/test');
const {login}=require('./helpers');

async function openEditor(page){
 await login(page,'e2e_admin',{workspace:false});
 const book={id:'roundtrip',name:'Check',steps:[{name:'First',command:'id',timeout:30},{name:'Second',command:'pwd',timeout:30}],stop_on_error:true};
 await page.route('**/api/automation/state',r=>r.fulfill({json:{enabled:true,runbooks:[book],profiles:[]}}));
 await page.goto('/automation');await page.locator('[data-auto-tab=runbooks]').click();
}

test('keyboard reordering keeps focus on the moved step and preserves edits',async({page})=>{
 await openEditor(page);await page.setViewportSize({width:390,height:667});
 const rows=page.locator('#runbookSteps > .automation-step');
 const move=rows.first().getByRole('button',{name:'Move step down',exact:true});
 await move.focus();await page.keyboard.press('Enter');
 await expect(rows.last().locator('[data-field=name]')).toHaveValue('First');
 await expect(rows.last().getByRole('button',{name:'Move step down',exact:true})).toBeFocused();
 await rows.last().getByRole('button',{name:'Move step up',exact:true}).focus();await page.keyboard.press('Enter');
 await expect(rows.first().locator('[data-field=name]')).toHaveValue('First');
 await expect(rows.first().getByRole('button',{name:'Move step up',exact:true})).toBeFocused();
 await rows.first().getByRole('button',{name:'Move step down',exact:true}).click();
 await rows.last().locator('[data-field=name]').fill('Changed first');
 await page.locator('#automationStepDetail textarea').fill('id -u');
 await rows.first().locator('[data-field=name]').focus();
 await expect(page.locator('#automationStepDetail textarea')).toHaveValue('pwd');
 await rows.last().locator('[data-field=name]').focus();
 await expect(page.locator('#automationStepDetail textarea')).toHaveValue('id -u');
});

test('unfinished schedule inputs survive a targets roundtrip without reverting silently',async({page})=>{
 await openEditor(page);await page.setViewportSize({width:390,height:667});
 await page.locator('#openSchedule').click();
 await page.locator('#scheduleFrequency').selectOption('daily');
 await page.locator('#scheduleTime').fill('14:25');
 await page.locator('#scheduleTime').fill('');
 await page.locator('[data-workspace-view=targets]').click();
 await page.locator('#openSchedule').click();
 await expect(page.locator('#scheduleFrequency')).toHaveValue('daily');
 await expect(page.locator('#scheduleTime')).toHaveValue('');
 await expect(page.locator('#scheduleSummary')).not.toContainText('14:25');
});
