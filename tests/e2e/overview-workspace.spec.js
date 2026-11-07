const {test, expect} = require('playwright/test');
const {login, installSshConnectTrap, sshAttempts, assertNoExternalRequests} = require('./helpers');

async function csrf(page) {
    return page.locator('meta[name="csrf-token"]').getAttribute('content');
}

async function setReachability(page, mode) {
    const response = await page.request.post('/api/account/preferences', {
        data: {overview_reachability: mode}, headers: {'X-CSRFToken': await csrf(page)},
    });
    expect(response.ok()).toBe(true);
}

async function openOverview(page) {
    await page.goto('/');
    await expect.poll(() => page.evaluate(() => window.ProfileManager?.profilesLoaded === true)).toBe(true);
    await expect(page.locator('#overviewHostList .od-host:not(.od-skeleton)').first()).toBeVisible();
}

test('dashboard shows inventory health without opening connections', async ({page}, info) => {
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    const probes = [];
    page.on('request', request => { if (request.url().endsWith('/api/overview/reachability')) probes.push(request.url()); });
    await login(page, 'e2e_admin', {workspace: false});
    await setReachability(page, 'manual');
    await openOverview(page);
    await installSshConnectTrap(page);

    const view = page.locator('#connectionOverview');
    await expect(view).toHaveAttribute('data-overview-workspace', /.*/);
    await expect(view).toHaveAttribute('data-reachability', 'manual');
    await expect(page.locator('#overviewTitle')).not.toBeEmpty();
    await expect(page.locator('#overviewStatusText')).not.toBeEmpty();
    // Readiness arrives from the server; the host tile never shows provisional numbers.
    await expect(page.locator('#odKpiHosts .od-kpi-value')).not.toHaveText('–');
    const total = await page.locator('#overviewHostList .od-host').count();
    expect(total).toBeGreaterThan(3);
    await expect(page.locator('#overviewHostTotal')).toHaveText(String(total));
    await expect(page.locator('#overviewHostList .od-host[data-state="unknown"]')).toHaveCount(0);
    await expect(page.locator('#odTopology svg, #odTopology .od-route-list').first()).toBeVisible();
    await expect(page.locator('#odAttention')).toBeVisible();
    await expect(page.locator('#odPlatforms .od-platform').first()).toBeVisible();

    // Manual mode never probes on its own.
    await page.waitForTimeout(500);
    expect(probes).toEqual([]);
    await page.screenshot({path: info.outputPath('dashboard-1440.png'), animations: 'disabled'});

    // Search narrows the list and reports the filtered count.
    await page.locator('#overviewSearch').fill('Ops first');
    await expect(page.locator('#overviewHostList .od-host')).toHaveCount(1);
    await expect(page.locator('#overviewHostTotal')).toHaveText(`1 / ${total}`);
    await page.locator('#overviewSearch').fill('no-such-host-anywhere');
    await expect(page.locator('#overviewHostsNoMatch')).toBeVisible();
    await page.locator('#overviewSearch').press('Escape');
    await expect(page.locator('#overviewHostList .od-host')).toHaveCount(total);

    expect(await sshAttempts(page)).toEqual([]);
    await assertNoExternalRequests(page);
    expect(errors).toEqual([]);
});

test('keyboard reaches search and moves between host actions', async ({page}) => {
    await login(page, 'e2e_admin', {workspace: false});
    await openOverview(page);
    await page.locator('body').click({position: {x: 5, y: 5}});
    await page.keyboard.press('/');
    await expect(page.locator('#overviewSearch')).toBeFocused();
    await page.keyboard.press('ArrowDown');
    const connects = page.locator('#overviewHostList .od-connect');
    await expect(connects.nth(0)).toBeFocused();
    await page.keyboard.press('ArrowDown');
    await expect(connects.nth(1)).toBeFocused();
    await page.keyboard.press('ArrowUp');
    await page.keyboard.press('ArrowUp');
    await expect(page.locator('#overviewSearch')).toBeFocused();
    // Typing "/" inside the search stays text input.
    await page.keyboard.type('a/b');
    await expect(page.locator('#overviewSearch')).toHaveValue('a/b');
});

test('reachability follows the account setting', async ({page}) => {
    const probes = [];
    page.on('request', request => { if (request.url().endsWith('/api/overview/reachability')) probes.push(request.method()); });
    await login(page, 'e2e_admin', {workspace: false});

    await setReachability(page, 'off');
    await openOverview(page);
    await expect(page.locator('#connectionOverview')).toHaveAttribute('data-reachability', 'off');
    await expect(page.locator('#odKpiReach [data-key="reach-check"]')).toHaveCount(0);
    await expect(page.locator('#odKpiReach a[href*="settings"]')).toBeVisible();
    await page.waitForTimeout(500);
    expect(probes).toEqual([]);

    await setReachability(page, 'manual');
    await openOverview(page);
    // Probe results are stubbed: the browser suite has no SSH servers.
    await page.route('**/api/overview/reachability', async route => {
        const ids = await page.evaluate(() => ProfileManager.profiles.map(profile => profile.id));
        const results = Object.fromEntries(ids.map((id, index) => [id, index === 0 ? {state: 'unreachable'} : {state: 'reachable', latency_ms: 3}]));
        await route.fulfill({json: {results, cached: false}});
    });
    await page.locator('#odKpiReach [data-key="reach-check"]').click();
    await expect.poll(() => probes.length).toBe(1);
    await expect(page.locator('#overviewHostList .od-host[data-state="unreachable"]')).toHaveCount(1);
    await expect(page.locator('#odKpiReach .od-kpi-value')).toContainText('/');

    await page.unroute('**/api/overview/reachability');
    await page.route('**/api/overview/reachability', route => route.fulfill({json: {results: {}, cached: false}}));
    probes.length = 0;
    await setReachability(page, 'automatic');
    await openOverview(page);
    await expect.poll(() => probes.length).toBeGreaterThan(0);
    await setReachability(page, 'manual');
});

test('settings expose the reachability mode and keep it after reload', async ({page}) => {
    await login(page, 'e2e_admin', {workspace: false});
    await setReachability(page, 'manual');
    await page.goto('/settings#preferences');
    const select = page.locator('#settingsOverviewReachability');
    await expect(select).toHaveValue('manual');
    await select.selectOption('off');
    await expect(select).toHaveAttribute('data-saved', 'off');
    await page.reload();
    await expect(page.locator('#settingsOverviewReachability')).toHaveValue('off');
    await page.locator('#settingsOverviewReachability').selectOption('manual');
    await expect(page.locator('#settingsOverviewReachability')).toHaveAttribute('data-saved', 'manual');
});

test('dashboard stays contained on phones and opens the full route map', async ({page}, info) => {
    await login(page, 'e2e_admin', {workspace: false});
    for (const width of [375, 768, 1440, 2560]) {
        await page.setViewportSize({width, height: 900});
        await openOverview(page);
        const overflow = await page.locator('#connectionOverview').evaluate(element => element.scrollWidth - element.clientWidth);
        expect(overflow, `no horizontal scroll at ${width}px`).toBeLessThanOrEqual(1);
        if (width < 640) await expect(page.locator('#odTopology .od-route-list')).toBeVisible();
        else await expect(page.locator('#odTopology svg')).toBeVisible();
        await page.screenshot({path: info.outputPath(`dashboard-${width}.png`), animations: 'disabled'});
    }
    await page.setViewportSize({width: 1440, height: 900});
    await openOverview(page);
    await page.locator('#overviewOpenMap').click();
    await expect(page.locator('#overviewRouteMap')).toBeVisible();
    await page.locator('#overviewRouteMap [data-route-map-expand]').first().click();
    await expect(page.locator('#overviewHostList')).toBeVisible();
});

test('reduced motion shows the final state immediately', async ({page}) => {
    await page.emulateMedia({reducedMotion: 'reduce'});
    await login(page, 'e2e_admin', {workspace: false});
    await openOverview(page);
    const animated = await page.locator('#connectionOverview').evaluate(root => [...root.querySelectorAll('*')]
        .filter(element => {
            const style = getComputedStyle(element);
            return style.animationName !== 'none' && parseFloat(style.animationDuration) > 0.01;
        }).length);
    expect(animated).toBe(0);
});

test('connecting from the expanded route map closes the map once', async ({page}) => {
    await login(page, 'e2e_admin', {workspace: false});
    await openOverview(page);
    await installSshConnectTrap(page);
    await page.locator('#overviewOpenMap').click();
    const dialog = page.locator('dialog.ssh-map-dialog');
    await expect(dialog).toBeVisible();
    await dialog.locator('.overview-host-connect').first().click();
    await expect(dialog).toBeHidden();
    await expect(page.locator('#connectionOverview')).toBeHidden();
});
