const {test, expect} = require('playwright/test');
const {login} = require('./helpers');

async function setPanels(page, panels) {
    const token = await page.locator('meta[name="csrf-token"]').getAttribute('content');
    expect((await page.request.put('/api/overview/preferences', {data:{panels}, headers:{'X-CSRFToken':token}})).ok()).toBe(true);
}

test.beforeEach(async ({page}) => {
    await page.setViewportSize({width:1440, height:900});
    await page.emulateMedia({reducedMotion:'reduce'});
    await page.route('**/api/overview/status', route => route.fulfill({json:{generated_at:1, hosts:[]}}));
    await login(page, 'e2e_admin', {workspace:false});
    await setPanels(page, [
        {id:'attention', w:12, h:40, hidden:false},
        {id:'topology', w:12, h:30, hidden:false},
        {id:'hosts', w:12, h:30, hidden:false},
        {id:'activity', w:12, h:100, hidden:false},
    ]);
    await page.reload();
    await page.waitForFunction(() => ProfileManager.profilesLoaded && JumpHostManager.loaded);
    await page.evaluate(() => {
        JumpHostManager.setJumpHosts([{id:'wheel-gateway', name:'Wheel gateway'}]);
        ProfileManager.setProfiles(Array.from({length:30}, (_, i) => ({id:`wheel-${i}`, name:`Wheel host ${i}`, host:`192.0.2.${i+1}`, username:'operator', jump_host_id:i%2 ? 'wheel-gateway' : null})));
    });
    await expect(page.locator('#overviewHostList .od-host')).toHaveCount(30);
});
test.afterEach(async ({page}) => { await setPanels(page, null); });

async function positionPanel(page, selector) {
    await page.locator(selector).evaluate(el => {
        const scroller = document.getElementById('connectionOverview');
        scroller.scrollTop += el.getBoundingClientRect().top - scroller.getBoundingClientRect().top - 100;
    });
    const box = await page.locator(selector).boundingBox();
    await page.mouse.move(box.x + box.width / 2, box.y + Math.min(80, box.height / 2));
}
const scrollTop = page => page.locator('#connectionOverview').evaluate(el => el.scrollTop);

test('wheel over a fixed-height panel without overflow scrolls the overview', async ({page}) => {
    const selector = '#odAttention > .od-panel-body';
    await positionPanel(page, selector);
    expect(await page.locator(selector).evaluate(el => el.scrollHeight <= el.clientHeight)).toBe(true);
    const before = await scrollTop(page);
    await page.mouse.wheel(0, 220);
    await expect.poll(() => scrollTop(page)).toBeGreaterThan(before + 100);
});

test('overflowing fixed-height hosts retain internal scrolling', async ({page}) => {
    const selector = '[data-panel="hosts"] > .od-panel-body';
    const body = page.locator(selector);
    await positionPanel(page, selector);
    const before = await scrollTop(page);
    expect(await body.evaluate(el => el.scrollHeight > el.clientHeight)).toBe(true);
    await page.mouse.wheel(0, 160);
    await expect.poll(() => body.evaluate(el => el.scrollTop)).toBeGreaterThan(40);
    expect(Math.abs(await scrollTop(page) - before)).toBeLessThan(2);
});

test('fixed-height hosts chain to the overview when already at their scroll edge', async ({page}) => {
    const selector = '[data-panel="hosts"] > .od-panel-body';
    const body = page.locator(selector);
    await positionPanel(page, selector);
    for (let attempt = 0; attempt < 20; attempt += 1) {
        const position = await body.evaluate(el => ({top:el.scrollTop, end:el.scrollHeight - el.clientHeight}));
        if (position.end - position.top < 2) break;
        await page.mouse.wheel(0, 300);
        await expect.poll(() => body.evaluate(el => el.scrollTop)).toBeGreaterThan(position.top);
    }
    await expect.poll(() => body.evaluate(el => Math.abs(el.scrollHeight - el.clientHeight - el.scrollTop))).toBeLessThan(2);
    // Leave and re-enter after the completed internal scroll gesture.
    await page.mouse.move(5, 50);
    await positionPanel(page, selector);
    const atEdge = await scrollTop(page);
    await page.mouse.wheel(0, 240);
    await expect.poll(() => scrollTop(page)).toBeGreaterThan(atEdge + 100);
});

test('inline routes allow page scrolling while the expanded map retains wheel zoom', async ({page}) => {
    await positionPanel(page, '#odTopology');
    const before = await scrollTop(page);
    await page.mouse.wheel(0, 220);
    await expect.poll(() => scrollTop(page)).toBeGreaterThan(before + 100);
    await expect(page.locator('dialog.ssh-map-dialog')).toBeHidden();
    await page.locator('#overviewOpenMap').click();
    const viewport = page.locator('#overviewRouteMap .ssh-route-viewport');
    const output = page.locator('#overviewRouteMap output');
    const zoom = await output.innerText();
    const box = await viewport.boundingBox();
    await page.mouse.move(box.x + 10, box.y + 10);
    await page.mouse.wheel(0, -120);
    await expect(output).not.toHaveText(zoom);
});


test('wheel at the top of a fixed panel scrolls the overview upward', async ({page}) => {
    const selector = '[data-panel="hosts"] > .od-panel-body';
    await positionPanel(page, selector);
    expect(await page.locator(selector).evaluate(el => el.scrollTop)).toBe(0);
    const before = await scrollTop(page);
    await page.mouse.wheel(0, -220);
    await expect.poll(() => scrollTop(page)).toBeLessThan(before - 100);
});

test('panel edge forwarding respects zoom modifiers and normalizes wheel units', async ({page}) => {
    const selector = '[data-panel="hosts"] > .od-panel-body';
    await positionPanel(page, selector);
    const result = await page.locator(selector).evaluate(body => {
        const overview = document.getElementById('connectionOverview');
        // Keep enough upward space after the work-first section moved below the board.
        overview.scrollTop = overview.clientHeight + 32;
        const emit = options => {
            const before = overview.scrollTop;
            const event = new WheelEvent('wheel', {bubbles:true, cancelable:true, deltaY:-1, ...options});
            body.dispatchEvent(event);
            return {canceled:event.defaultPrevented, moved:before-overview.scrollTop};
        };
        return {ctrl:emit({ctrlKey:true}), meta:emit({metaKey:true}), line:emit({deltaMode:1}), page:emit({deltaMode:2}), height:overview.clientHeight};
    });
    expect(result.ctrl).toEqual({canceled:false, moved:0});
    expect(result.meta).toEqual({canceled:false, moved:0});
    expect(result.line).toEqual({canceled:true, moved:16});
    expect(result.page).toEqual({canceled:true, moved:result.height});
});
