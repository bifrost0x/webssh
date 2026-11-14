const {test, expect} = require('playwright/test');
const {login} = require('./helpers');
const path = require('node:path');

for (const width of [1440, 390]) {
    test(`support report is deliberate, previewed and downloadable at ${width}`, async ({page}) => {
        await page.setViewportSize({width, height: 960});
        await login(page, 'e2e_user');
        let reports = 0;
        page.on('request', request => { if (request.url().endsWith('/api/account/support-report')) reports++; });
        await page.goto('/settings');
        expect(reports).toBe(0);
        await page.getByRole('button', {name: 'Support report', exact: true}).click();
        const dialog = page.getByRole('dialog', {name: 'Support report', exact: true});
        await expect(dialog).toBeVisible();
        expect(reports).toBe(0);
        await dialog.getByLabel('Area', {exact: true}).selectOption('files');
        await dialog.getByLabel('Error reference (optional)', {exact: true}).fill('SMB-ABCDEF123456');
        await dialog.getByRole('button', {name: 'Generate preview', exact: true}).click();
        await expect(dialog.locator('pre')).toContainText('SMB-ABCDEF123456');
        const shown = await dialog.locator('pre').textContent();
        expect(JSON.parse(shown).deployment).toBeUndefined();
        expect(shown).not.toContain('e2e_user');
        await page.evaluate(() => Object.defineProperty(navigator, 'clipboard', {
            configurable: true, value: {writeText: async text => { window.__copiedReport = text; }},
        }));
        await dialog.getByRole('button', {name: 'Copy report', exact: true}).click();
        await expect.poll(() => page.evaluate(() => window.__copiedReport)).toBe(shown + '\n');
        const downloadEvent = page.waitForEvent('download');
        await dialog.getByRole('button', {name: 'Download report', exact: true}).click();
        const download = await downloadEvent;
        const stream = await download.createReadStream();
        const chunks = [];
        for await (const chunk of stream) chunks.push(chunk);
        expect(Buffer.concat(chunks).toString('utf8')).toBe(shown + '\n');
        expect(await dialog.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
        await page.screenshot({path: path.join('plans', 'support-report', `report-${width}.png`), fullPage: false});
        await dialog.getByLabel('Area', {exact: true}).selectOption('ssh');
        await expect(dialog.getByRole('button', {name: 'Download report', exact: true})).toBeDisabled();
        await page.keyboard.press('Escape');
        await expect(dialog).toHaveCount(0);
        await expect(page.getByRole('button', {name: 'Support report', exact: true})).toBeFocused();
        expect(page.__externalRequests).toEqual([]);
    });

    test(`continue working follows all overview panels at ${width}`, async ({page}) => {
        await page.setViewportSize({width, height: 960});
        await login(page, 'e2e_admin', {workspace: false});
        const overview = page.locator('#overviewNavBtn');
        if (await overview.isVisible()) await overview.click();
        const section = page.locator('#overviewWorkFirst');
        await expect(section).toBeVisible();
        expect(await section.evaluate(element => {
            const board = document.getElementById('odBoard');
            return Boolean(board.compareDocumentPosition(element) & Node.DOCUMENT_POSITION_FOLLOWING)
                && element.getBoundingClientRect().top >= board.getBoundingClientRect().bottom;
        })).toBe(true);
        await section.scrollIntoViewIfNeeded();
        await page.screenshot({path: path.join('plans', 'support-report', `overview-bottom-${width}.png`)});
        await page.locator('#overviewFirstConnection summary').click();
        await expect(page.locator('#overviewSetupHost')).toBeVisible();
    });
}

test('failed report remains empty and can be explicitly retried', async ({page}) => {
    await login(page, 'e2e_user');
    await page.goto('/settings');
    await page.route('**/api/account/support-report', route => route.fulfill({
        status: 503, contentType: 'application/json', body: JSON.stringify({error: 'private-server-details'}),
    }), {times: 1});
    await page.getByRole('button', {name: 'Support report', exact: true}).click();
    const dialog = page.getByRole('dialog', {name: 'Support report', exact: true});
    await dialog.getByRole('button', {name: 'Generate preview', exact: true}).click();
    await expect(dialog.getByRole('status')).toContainText('could not be generated');
    await expect(dialog).not.toContainText('private-server-details');
    await expect(dialog.getByRole('button', {name: 'Copy report', exact: true})).toBeDisabled();
    await dialog.getByRole('button', {name: 'Generate preview', exact: true}).click();
    await expect(dialog.locator('pre')).toContainText('generated_at');
    await expect(dialog.getByRole('button', {name: 'Download report', exact: true})).toBeEnabled();
});
