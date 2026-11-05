const {test, expect} = require('playwright/test');
const {login} = require('./helpers');

for (const staleFailure of [false, true]) {
test(`audit search ignores a late older ${staleFailure ? 'failure' : 'result'}`, async ({page}) => {
    await login(page);
    await page.goto('/settings#audit');
    await expect(page.locator('#auditSearch')).toBeVisible();
    let releaseOld;
    let oldStarted;
    const started = new Promise(resolve => { oldStarted = resolve; });
    const delayed = new Promise(resolve => { releaseOld = resolve; });
    await page.route('**/admin/api/audit?**', async route => {
        const query = new URL(route.request().url()).searchParams.get('q');
        if (query === 'older') {
            oldStarted(); await delayed;
            if (staleFailure) {
                await route.fulfill({status:503,json:{error:'obsolete-request-error'}});
                return;
            }
        }
        await route.fulfill({json:{total:1,offset:0,items:[{timestamp:'2026-11-02T12:00:00Z',level:'INFO',logger:'audit',message:`result-${query}`}]}});
    });
    await page.locator('#auditSearch').fill('older');
    await started;
    await page.locator('#auditSearch').fill('latest');
    await expect(page.locator('#adminAuditBody')).toContainText('result-latest');
    const olderResponse = page.waitForResponse(response => response.url().includes('q=older'));
    releaseOld();
    await olderResponse;
    // Allow the response handler to render before asserting that it was ignored.
    await page.waitForTimeout(100);
    await expect(page.locator('#adminAuditBody')).toContainText('result-latest');
    await expect(page.locator('#adminAuditBody')).not.toContainText('result-older');
    await expect(page.locator('#notificationContainer')).not.toContainText('obsolete-request-error');
});
}
