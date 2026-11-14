const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');
const path = require('node:path');
const fs = require('node:fs');
const run = (id, status) => ({id, name: status === 'failed' ? 'Check backup storage' : 'Inspect system health', status,
    created_at:'2026-11-14T08:30:00Z', finished_at:'2026-11-14T08:30:03Z', targets:[{
        name:'lab-server', host:'lab-server.example', username:'operator', status,
        steps:[{name:status === 'failed' ? 'Check free space' : 'System uptime', status, exit_code:status === 'failed' ? 1 : 0, duration:3,
            reason:status === 'failed' ? 'nonzero_exit' : '', stdout:status === 'failed' ? '/backup: 98% used\n' : 'up 14 days, load average: 0.12, 0.08, 0.05\n', stderr:status === 'failed' ? 'Available storage is below the configured threshold.\n' : ''}]}]});
test.afterEach(async ({page}) => assertNoExternalRequests(page));
for (const width of [1440,390]) {
    test(`results hierarchy, filters and guidance at ${width}px`, async ({page}) => {
        await page.setViewportSize({width,height:1000});
        await login(page,'e2e_admin',{workspace:false});
        let runs = [run('failed-fixture','failed'),run('success-fixture','succeeded')];
        await page.route('**/api/automation/runs',route=>route.fulfill({json:{runs}}));
        await page.goto('/automation');
        await page.locator('[data-auto-tab="runs"]').click();
        await expect(page.locator('.automation-run')).toHaveCount(2);
        await expect(page.locator('#workflowNotifications')).toHaveCount(0);
        await expect(page.locator('.automation-results-help')).not.toHaveAttribute('open','');
        await page.locator('.automation-run-diagnostic > summary').first().click();
        await expect(page.locator('.automation-run-output').first()).toContainText('Available storage is below');
        await expect(page.locator('.automation-run').first().getByRole('link',{name:'Export JSON'})).toHaveAttribute('href',/failed-fixture\/export\?format=json$/);
        expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
        const folder=path.join(process.cwd(),'plans','results-refinement'); fs.mkdirSync(folder,{recursive:true});
        await page.screenshot({path:path.join(folder,`results-detail-${width}.png`),fullPage:true});
        if (width < 600) {
            await page.locator('.automation-run').first().locator(':scope > summary').click();
            await page.locator('.automation-main').evaluate(element => { element.scrollTop = 0; });
            await page.evaluate(() => window.scrollTo(0, 0));
        }
        await page.screenshot({path:path.join(folder,`results-populated-${width}.png`),fullPage:true});
        await page.locator('#runStatusFilter').selectOption('succeeded');
        await expect(page.locator('.automation-run:visible')).toHaveCount(1);
        await expect(page.locator('.automation-run:visible')).toContainText('Inspect system health');
        await page.locator('#runSearch').fill('missing fixture');
        await expect(page.locator('#runFilterEmpty')).toBeVisible();
        await page.locator('#runSearch').fill('');
        await page.locator('#runStatusFilter').selectOption('');
        await page.locator('.automation-results-help > summary').click();
        await expect(page.locator('[data-auto-i18n="retentionExplanation"]')).toBeVisible();
        await page.locator('.automation-results-help > summary').click();
        runs=[]; await page.locator('#refreshRuns').click();
        await expect(page.getByRole('heading',{name:'No results yet'})).toBeVisible();
        await expect(page.locator('#clearRuns')).toBeDisabled();
        await page.screenshot({path:path.join(folder,`results-empty-${width}.png`),fullPage:true});
        await page.getByRole('button',{name:'Choose a workflow',exact:true}).click();
        await expect(page.locator('#auto-library')).toBeVisible();
    });
}
