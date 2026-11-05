const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');
test.afterEach(async ({page}) => assertNoExternalRequests(page));

test('history filters preserve expanded diagnostics and find hosts without searching command output', async ({page}, testInfo) => {
    await login(page, 'e2e_admin', {workspace:false});
    const runs = ['failed','succeeded'].map((status,index) => ({id:'filter-'+index,name:'Maintenance '+index,created_at:'2026-11-04T00:00:00Z',status,targets:[{name:index ? 'Backup' : 'Gateway',host:'lab.invalid',username:'operator',status,steps:[{name:'Check',status,exit_code:index ? 0 : 1,reason:index ? null : 'nonzero_exit',duration:1,stdout:'private-output-token',stderr:'',output_truncated:false}]}]}));
    await page.route('**/api/automation/runs', route=>route.fulfill({json:{runs}}));
    await page.goto('/automation'); await page.locator('[data-auto-tab="runs"]').click();
    const first = page.locator('.automation-run').first();
    await first.locator('.automation-run-diagnostic > summary').click();
    await page.locator('#runSearch').fill('Backup');
    await expect(first).toBeHidden();
    await expect(page.locator('.automation-run:visible')).toHaveCount(1);
    await page.locator('#runStatusFilter').selectOption('attention');
    await expect(page.locator('#runFilterEmpty')).toBeVisible();
    await page.locator('#runSearch').fill('');
    await expect(first).toBeVisible();
    await expect(first.locator('.automation-run-diagnostic')).toHaveAttribute('open','');
    await page.locator('#runSearch').fill('private-output-token');
    await expect(page.locator('#runFilterEmpty')).toBeVisible();
    await page.locator('#runSearch').fill('');
    for (const width of [390,1440]) {
        await page.setViewportSize({width,height:900});
        expect(await page.evaluate(()=>document.documentElement.scrollWidth <= innerWidth)).toBe(true);
        await page.screenshot({path:testInfo.outputPath('history-'+width+'.png'),animations:'disabled'});
    }
});

test('package confirmation abort explains the failed run without changing its exit status', async ({page}) => {
    await login(page, 'e2e_admin', {workspace:false});
    const step={name:'Upgrade',status:'failed',reason:'nonzero_exit',exit_code:1,duration:0.75,stdout:'Paketlisten werden gelesen…\nFortfahren? [J/n] Abbruch.\n',stderr:'WARNING: apt does not have a stable CLI interface.',output_truncated:false};
    await page.route('**/api/automation/runs',route=>route.fulfill({json:{runs:[{id:'confirmation-run',name:'Upgrade',created_at:'2026-11-04T00:00:00Z',status:'failed',targets:[{name:'Test host',username:'operator',host:'test.invalid',status:'failed',steps:[step]}]}]}}));
    await page.goto('/automation');await page.locator('[data-auto-tab="runs"]').click();
    const item=page.locator('.automation-run-diagnostic');await item.locator('summary').click();
    await expect(item).toContainText('asked for confirmation and aborted');
    await expect(item).toContainText('Exit code: 1');
    await expect(item.locator('[data-result-key=stdout] pre')).toContainText('Fortfahren?');
});

test('run diagnostics preserve disclosures, selection and scroll across polling and render only text', async ({page}, testInfo) => {
    await login(page, 'e2e_admin', {workspace:false});
    const output = '<img src=x onerror="window.outputExecuted=true">\n' + 'long-output '.repeat(700) + '\n' + 'line\n'.repeat(100);
    const step = {name:'Inspect output',status:'failed',exit_code:1,duration:0.12,reason:'nonzero_exit',stdout:output,stderr:'arbitrary remote failure',output_truncated:true};
    const runs = [{id:'diagnostic-run',name:'Output evidence',created_at:'2026-11-03T10:00:00Z',status:'failed',targets:[{name:'Lab',username:'operator',host:'host.invalid',status:'failed',steps:[step,{name:'Legacy',status:'unknown',exit_code:null,duration:1},{...step,name:'Timeout',status:'unknown',exit_code:null,reason:'timeout'}]}]}];
    await page.route('**/api/automation/runs', route => route.fulfill({json:{runs}}));
    await page.goto('/automation');
    await page.locator('[data-auto-tab="runs"]').click();
    const diagnostic = page.locator('.automation-run-diagnostic').first();
    await diagnostic.locator('summary').click();
    await expect(diagnostic.locator('[data-result-key=stdout] pre')).toContainText('<img src=x');
    await expect(diagnostic).toContainText('Exit code: 1');
    await expect(diagnostic).toContainText('Duration: 0.12s');
    await expect(diagnostic).toContainText('nonzero exit code');
    await expect(diagnostic).toContainText('Output truncated');
    expect(await page.evaluate(() => window.outputExecuted)).toBeUndefined();
    await expect(diagnostic.locator('img')).toHaveCount(0);
    await diagnostic.evaluate(el => {
        window.originalDiagnostic = el;
        const pre = el.querySelector('pre'); pre.scrollTop = 80;
        const range = document.createRange(); range.setStart(pre.firstChild,0);range.setEnd(pre.firstChild,10);
        getSelection().removeAllRanges();getSelection().addRange(range);
    });
    runs[0].targets[0].steps[2].duration = 2;
    // Refresh invokes the same path as the periodic polling timer.
    await page.locator('#refreshRuns').evaluate(el => el.click());
    await expect(page.locator('.automation-run-diagnostic').nth(2)).toContainText('Duration: 2s');
    expect(await diagnostic.evaluate(el => el === window.originalDiagnostic && el.open && el.querySelector('pre').scrollTop === 80 && getSelection().toString().length === 10)).toBe(true);
    await diagnostic.locator('summary').click();
    runs[0].targets[0].steps[2].duration = 3;
    await page.locator('#refreshRuns').evaluate(el => el.click());
    await expect(page.locator('.automation-run-diagnostic').nth(2)).toContainText('Duration: 3s');
    expect(await diagnostic.evaluate(el => el.open)).toBe(false);
    const legacy = page.locator('.automation-run-diagnostic').nth(1);
    await legacy.locator('summary').focus(); await page.keyboard.press('Enter');
    await expect(legacy).toContainText('No command output was stored');
    await expect(legacy.locator('pre').first()).not.toBeVisible();
    await page.locator('.automation-run-diagnostic').nth(2).locator('summary').click();
    await expect(page.locator('.automation-run-diagnostic').nth(2)).toContainText('Remote work may still be running');
    await diagnostic.locator('summary').click();
    for (const width of [360,768,1366]) {
        await page.setViewportSize({width,height:900});
        for (const theme of ['paper','werkbank','noir']) {
            await page.evaluate(value => {document.body.dataset.theme=value;},theme);
            expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
        }
        await page.screenshot({path:testInfo.outputPath('diagnostics-'+width+'.png'),animations:'disabled'});
    }
});
