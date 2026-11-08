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

test('finished runs can be deleted one by one or together while running work stays', async ({page}, testInfo) => {
    await login(page, 'e2e_admin', {workspace:false});
    const step = status => ({name:'Update package lists',status,exit_code:status === 'succeeded' ? 0 : status === 'failed' ? 1 : null,duration:1.2,reason:status === 'failed' ? 'nonzero_exit' : null,stdout:'',stderr:'',output_truncated:false});
    const run = (id, status, hosts) => ({id,name:'Updates for Linux',created_at:'2026-11-08T12:0'+id.length+':00Z',finished_at:status === 'running' ? undefined : '2026-11-08T12:01:06Z',status,
        targets:hosts.map(([name, hostStatus]) => ({id:name,name,host:name.toLowerCase() + '.invalid',username:'operator',status:hostStatus,reason:null,steps:[step(hostStatus)]}))});
    let runs = [run('live', 'running', [['Nextcloud','running']]),
        run('done', 'succeeded', [['Nextcloud','succeeded'],['Immich','succeeded'],['Node','succeeded']]),
        run('broken', 'failed', [['Nextcloud','succeeded'],['Node','failed']])];
    const requests = [];
    await page.route('**/api/automation/runs**', route => {
        const request = route.request();
        const path = new URL(request.url()).pathname;
        if (request.method() === 'DELETE') { requests.push(['DELETE', path]); runs = runs.filter(item => !path.endsWith('/' + item.id)); return route.fulfill({json:{deleted:1}}); }
        if (path.endsWith('/clear')) { requests.push(['POST', path]); const removed = runs.filter(item => item.status !== 'running').length; runs = runs.filter(item => item.status === 'running'); return route.fulfill({json:{deleted:removed}}); }
        return route.fulfill({json:{runs}});
    });
    await page.goto('/automation'); await page.locator('[data-auto-tab="runs"]').click();
    const cards = page.locator('#runHistory > .automation-run');
    await expect(cards).toHaveCount(3);
    await expect(cards.nth(0).locator('.automation-run-delete')).toBeHidden();
    await expect(cards.nth(1)).toHaveAttribute('data-state', 'succeeded');
    await expect(cards.nth(1).locator('.automation-run-host')).toHaveText(['Nextcloud','Immich','Node','']);
    await expect(cards.nth(2).locator('.automation-run-host[data-state="failed"]')).toHaveText('Node');
    for (const width of [390, 1440]) {
        await page.setViewportSize({width,height:900});
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
        await page.screenshot({path:testInfo.outputPath('run-cards-'+width+'.png'),animations:'disabled',fullPage:true});
    }
    await cards.nth(2).locator('.automation-run-delete').click();
    await expect(cards.nth(2)).not.toHaveAttribute('open', '');
    await expect(page.locator('#automationPrompt')).toBeVisible();
    await page.locator('#promptForm button[type="submit"]').click();
    await expect(cards).toHaveCount(2);
    await page.locator('#clearRuns').click();
    await expect(page.locator('#promptHint')).toContainText('1 finished');
    await page.locator('#promptForm button[type="submit"]').click();
    await expect(cards).toHaveCount(1);
    await expect(cards.first()).toHaveAttribute('data-state', 'running');
    expect(requests).toEqual([['DELETE','/api/automation/runs/broken'],['POST','/api/automation/runs/clear']]);
});
