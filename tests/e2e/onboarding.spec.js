const {test, expect} = require('playwright/test');
const {login} = require('./helpers');

test('tour crosses workspaces, handles small screens and saves completion', async ({page}) => {
    await login(page, 'e2e_admin', {workspace: false, tour: 'new'});
    await page.request.post('/api/account/tour', {data:{state:'new'},headers:{'X-CSRFToken':await page.locator('meta[name="csrf-token"]').getAttribute('content')}});
    await page.reload();
    await expect(page.locator('.intro-tour')).toBeVisible();
    await page.locator('.intro-tour').getByRole('button', {name:'Skip tour',exact:true}).click();
    await expect(page.locator('.intro-tour')).toHaveCount(0);
    // A skipped tour stays closed across page loads.
    const reloadedTour = page.waitForResponse(response => response.url().endsWith('/api/account/tour') && response.request().method() === 'GET');
    await page.reload();
    expect((await (await reloadedTour).json()).state).toBe('dismissed');
    await expect(page.locator('.intro-tour')).toHaveCount(0);
    await page.locator('#accountBtnHeader').click();
    await page.locator('#restartTour').click();
    const tour = page.locator('.intro-tour');
    await expect(tour).toBeVisible();
    for (let step = 0; step < 8; step++) {
        await expect(tour.locator('header span')).toHaveText(`${step + 1} / 8`);
        for (const width of [390, 1440]) {
            await page.setViewportSize({width, height: 800});
            const box = await tour.boundingBox();
            expect(box.x).toBeGreaterThanOrEqual(0);
            expect(box.x + box.width).toBeLessThanOrEqual(width);
            await expect(tour.getByRole('button', {name: step === 7 ? 'Get started' : 'Next', exact: true})).toBeInViewport();
        }
        const help = tour.getByRole('link', {name: 'Open documentation'});
        expect(await help.getAttribute('href')).toMatch(/^https:\/\/github\.com\/bifrost0x\/webssh\/wiki\//);
        if (step === 5) await expect(page.locator('body')).toHaveAttribute('data-primary-workspace', 'automation');
        if (step === 2) {
            await tour.getByRole('button', {name: 'Back', exact: true}).click();
            await expect(tour.locator('h2')).toHaveText('Hosts and credentials');
            await tour.getByRole('button', {name: 'Next', exact: true}).click();
        }
        if (step === 7) { await expect(tour.getByRole('button', {name: 'Get started'})).toBeDisabled(); await tour.locator('#introAcknowledge').check(); }
        await tour.getByRole('button', {name: step === 7 ? 'Get started' : 'Next', exact: true}).click();
    }
    await expect(tour).toHaveCount(0);
    await page.reload();
    await expect.poll(async () => (await (await page.request.get('/api/account/tour')).json()).state).toBe('completed');
    await expect(tour).toHaveCount(0);
});

test('a failed save does not keep the tour open when it is skipped', async ({page}) => {
    await login(page, 'e2e_admin', {workspace: false, tour: 'new'});
    await page.request.post('/api/account/tour', {data:{state:'new'},headers:{'X-CSRFToken':await page.locator('meta[name="csrf-token"]').getAttribute('content')}});
    await page.reload();
    const tour = page.locator('.intro-tour');
    await expect(tour).toBeVisible();
    // An expired page or a lost connection makes the save fail.
    await page.route('**/api/account/tour', route => route.request().method() === 'POST'
        ? route.fulfill({status: 400, json: {error: 'csrf_expired'}})
        : route.continue());
    await page.keyboard.press('Escape');
    await expect(tour).toHaveCount(0);
    // Nothing was saved, so the tour comes back on the next load.
    await page.unroute('**/api/account/tour');
    await page.reload();
    await expect(tour).toBeVisible();
    await tour.getByRole('button', {name:'Skip tour',exact:true}).click();
    await expect(tour).toHaveCount(0);
});
