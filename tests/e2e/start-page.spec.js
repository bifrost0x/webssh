const {test,expect}=require('playwright/test');
const {login}=require('./helpers');
test('start page persists per account and leaves direct automation links intact',async({page})=>{
 await login(page,'e2e_admin',{workspace:false});
 await page.goto('/settings#preferences');
 const select=page.locator('#settingsStartPage');await expect(select).toHaveValue('overview');
 await select.selectOption('workspaces');await expect(select).toHaveAttribute('data-saved','workspaces');
 await page.context().clearCookies();await login(page,'e2e_admin',{workspace:false});await expect(page.locator('body')).toHaveAttribute('data-primary-workspace','workspaces');
 await page.goto('/automation');await expect(page.locator('body')).toHaveAttribute('data-primary-workspace','automation');
 await page.setViewportSize({width:390,height:800});await page.goto('/settings#preferences');await expect(select).toHaveValue('workspaces');await select.scrollIntoViewIfNeeded();await expect(select).toBeInViewport();
 await select.selectOption('overview');await expect(select).toHaveAttribute('data-saved','overview');
 await page.context().clearCookies();await login(page,'e2e_admin',{workspace:false});await expect(page.locator('body')).toHaveAttribute('data-primary-workspace','overview');
 await page.goto('/settings#preferences');await page.locator('#settingsOverviewLayout').selectOption('classic');await expect(page.locator('#settingsOverviewLayout')).toHaveAttribute('data-saved','classic');await page.setViewportSize({width:1440,height:900});await page.goto('/');await expect(page.locator('#overviewQuickConnect')).toBeVisible();
 await page.goto('/settings#preferences');await page.locator('#settingsOverviewLayout').selectOption('dashboard');await expect(page.locator('#settingsOverviewLayout')).toHaveAttribute('data-saved','dashboard');
});
