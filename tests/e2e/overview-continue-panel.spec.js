const {test, expect} = require('playwright/test');
const {login, installSshConnectTrap, sshAttempts} = require('./helpers');

async function saveLayout(page, panels) {
    const token = await page.locator('meta[name="csrf-token"]').getAttribute('content');
    expect((await page.request.put('/api/overview/preferences', {data:{panels}, headers:{'X-CSRFToken':token}})).ok()).toBe(true);
}
async function storedLayout(page) {
    const html = await (await page.request.get('/')).text();
    return JSON.parse(html.match(/<script[^>]+id="overviewPreferences"[^>]*>([^<]+)<\/script>/)[1]).panels;
}
const order = page => page.locator('#odBoard > [data-panel]').evaluateAll(nodes => nodes
    .filter(node => node.dataset.userHidden !== 'true')
    .sort((a,b) => Number(a.style.order) - Number(b.style.order)).map(node => node.dataset.panel));

test.afterEach(async ({page}) => { await saveLayout(page, null); });

test('continue working joins legacy layouts and persists dragging, resizing, hiding and restore', async ({page}) => {
    await page.setViewportSize({width:1440, height:960});
    await page.emulateMedia({reducedMotion:'reduce'});
    await login(page, 'e2e_admin', {workspace:false});
    const legacy = await page.evaluate(() => OverviewLayout.defaults().filter(item => item.id !== 'continue')
        .map(item => ({...item, hidden:!['kpis','activity'].includes(item.id)})));
    await saveLayout(page, legacy);
    await page.reload();
    await installSshConnectTrap(page);
    const panel = page.locator('#overviewWorkFirst');
    await expect(panel).toHaveAttribute('data-panel', 'continue');
    await expect(panel).toHaveAttribute('data-width', '12');
    expect(await order(page)).toEqual(['kpis','activity','continue']);
    expect(await storedLayout(page)).toEqual(legacy);
    await page.locator('#overviewFirstConnection summary').click();
    await page.locator('#overviewCustomize').click();
    await panel.locator('[data-panel-handle]').hover();
    await page.mouse.down();
    const target = await page.locator('[data-panel="activity"]').boundingBox();
    await page.mouse.move(target.x + 10, target.y + 40, {steps:8});
    await page.mouse.up();
    expect(await order(page)).toEqual(['kpis','continue','activity']);

    await panel.locator('.od-resize').scrollIntoViewIfNeeded();
    const grip = await panel.locator('.od-resize').boundingBox();
    const box = await panel.boundingBox();
    await page.mouse.move(grip.x + 10, grip.y + 10);
    await page.mouse.down();
    await page.mouse.move(box.x + box.width / 2, box.y + 260, {steps:8});
    await page.mouse.up();
    await expect(panel).toHaveAttribute('data-fixed-height', 'true');
    expect(Number(await panel.getAttribute('data-width'))).toBeLessThan(12);
    const body = panel.locator(':scope > .od-panel-body');
    expect(await body.evaluate(el => el.scrollHeight > el.clientHeight)).toBe(true);
    await body.hover();
    await page.mouse.wheel(0, 160);
    await expect.poll(() => body.evaluate(el => el.scrollTop)).toBeGreaterThan(0);
    await body.evaluate(el => { el.scrollTop = 0; });
    await page.screenshot({path:'plans/continue-panel/resized-1440.png'});

    await page.getByRole('button', {name:'Hide Continue working', exact:true}).click();
    await expect(panel).toBeHidden();
    await page.locator('#odLayoutDone').click();
    await expect.poll(async () => (await storedLayout(page))?.find(item => item.id === 'continue')?.hidden).toBe(true);
    const saved = (await storedLayout(page)).find(item => item.id === 'continue');
    await page.reload();
    await expect(panel).toHaveAttribute('data-user-hidden', 'true');
    await expect(panel).toBeHidden();
    await page.locator('#overviewCustomize').click();
    await page.locator('[data-show-panel="continue"]').click();
    await expect(panel).toBeVisible();
    await expect(panel).toHaveAttribute('data-width', String(saved.w));
    await expect(panel).toHaveAttribute('data-fixed-height', 'true');
    await expect(panel.locator('[data-panel-handle]')).toBeFocused();
    await panel.locator('[data-panel-handle]').press('ArrowUp');
    expect((await order(page))[0]).toBe('continue');
    await page.getByRole('button', {name:'Fit Continue working to its content', exact:true}).click();
    await expect(panel).toHaveAttribute('data-fixed-height', 'false');
    await page.locator('#odLayoutReset').click();
    await page.locator('#odLayoutDone').click();
    await expect.poll(() => storedLayout(page)).toBe(null);
    expect((await order(page)).at(-1)).toBe('continue');
    await expect(panel).toHaveAttribute('data-width', '12');
    expect(await sshAttempts(page)).toEqual([]);
});

test('continue working stacks on mobile and can be hidden and restored with translated controls', async ({page}) => {
    await page.setViewportSize({width:390, height:900});
    await login(page, 'e2e_admin', {workspace:false});
    await saveLayout(page, [{id:'continue',w:3,h:12,hidden:false}]);
    await page.reload();
    await page.evaluate(() => window.i18n.setLanguage('de'));
    const panel = page.locator('#overviewWorkFirst');
    const box = await panel.boundingBox();
    const board = await page.locator('#odBoard').boundingBox();
    expect(Math.abs(box.width - board.width)).toBeLessThan(2);
    await panel.locator('summary').click();
    await expect(page.locator('#overviewSetupHost')).toBeVisible();
    expect(await panel.evaluate(el => el.scrollHeight <= el.clientHeight + 1)).toBe(true);
    await page.locator('#overviewCustomize').click();
    await panel.scrollIntoViewIfNeeded();
    await expect(panel.locator('[data-panel-handle]')).toHaveAttribute('aria-label', /Weiterarbeiten/);
    expect(await panel.evaluate(el => el.querySelector('.od-panel-tools').getBoundingClientRect().bottom
        <= el.querySelector('.od-panel-head').getBoundingClientRect().top)).toBe(true);
    await page.screenshot({path:'plans/continue-panel/edit-390.png'});
    await panel.getByRole('button', {name:/Weiterarbeiten ausblenden/}).click();
    await expect(panel).toBeHidden();
    await page.locator('#odLayoutDone').click();
    await expect.poll(async () => (await storedLayout(page))?.find(item => item.id === 'continue')?.hidden).toBe(true);
    await page.reload();
    await expect(panel).toBeHidden();
    await page.locator('#overviewCustomize').click();
    await page.locator('[data-show-panel="continue"]').click();
    await expect(panel).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});
