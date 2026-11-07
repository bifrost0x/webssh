const {test, expect} = require('playwright/test');
const {login, installSshConnectTrap, sshAttempts, assertNoExternalRequests} = require('./helpers');

// The e2e server is shared within a lane; restore the account's overview state even after a failure.
test.afterEach(async ({page}) => {
    const token = await page.locator('meta[name="csrf-token"]').getAttribute('content', {timeout: 1000}).catch(() => null);
    if (!token) return;
    const headers = {'X-CSRFToken': token};
    await page.request.post('/api/account/preferences', {data: {overview_reachability: 'manual', overview_layout: 'dashboard'}, headers}).catch(() => {});
    await page.request.put('/api/overview/preferences', {data: {panels: null, dismissed: []}, headers}).catch(() => {});
});

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
    // Reading the last stored result is allowed; a probe is a POST.
    page.on('request', request => { if (request.url().endsWith('/api/overview/reachability') && request.method() === 'POST') probes.push(request.url()); });
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
    page.on('request', request => { if (request.url().endsWith('/api/overview/reachability') && request.method() === 'POST') probes.push(request.method()); });
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
    // The map must not reopen behind the workspace, and exactly one connection starts.
    await expect.poll(() => sshAttempts(page).then(attempts => attempts.length)).toBe(1);
    await page.waitForTimeout(300);
    await expect(dialog).toBeHidden();
    expect((await sshAttempts(page)).length).toBe(1);
});

test('the last reachability result survives leaving and reloading the overview', async ({page}) => {
    await login(page, 'e2e_admin', {workspace: false});
    await setReachability(page, 'manual');
    const posts = [];
    const ids = await page.evaluate(() => ProfileManager.profiles.map(profile => profile.id));
    await page.route('**/api/overview/reachability', async route => {
        if (route.request().method() === 'POST') posts.push(1);
        const results = Object.fromEntries(ids.map(id => [id, {state: 'reachable', latency_ms: 4}]));
        await route.fulfill({json: {results, checked_at: Date.now() / 1000 - 120}});
    });
    await openOverview(page);
    await expect(page.locator('#odKpiReach .od-kpi-value')).toContainText('/');
    await expect(page.locator('#odKpiReach')).toContainText(/2 minutes ago|vor 2 Minuten/);
    await page.locator('#workspaceNavBtn').click();
    await page.locator('#overviewNavBtn').click();
    await expect(page.locator('#odKpiReach .od-kpi-value')).toContainText('/');
    expect(posts).toEqual([]);
});

async function settledAttention(page) {
    // Readiness and automation arrive after the first paint; count once they did.
    await expect(page.locator('#odKpiHosts .od-kpi-value')).not.toHaveText('–');
    await expect(page.locator('#overviewHostList .od-host[data-state="unknown"]')).toHaveCount(0);
    const rows = page.locator('#odAttention .od-list > li');
    let previous = -1;
    await expect.poll(async () => {
        const current = await rows.count();
        const stable = current === previous;
        previous = current;
        return stable;
    }, {intervals: [300, 300, 300, 500]}).toBe(true);
    return previous;
}

async function savePreferences(page, data) {
    const response = await page.request.put('/api/overview/preferences', {data, headers: {'X-CSRFToken': await csrf(page)}});
    expect(response.ok()).toBe(true);
}

test('attention items can be dismissed, stay dismissed and can be shown again', async ({page}) => {
    await login(page, 'e2e_admin', {workspace: false});
    await savePreferences(page, {dismissed: []});
    await openOverview(page);
    const panel = page.locator('#odAttention');
    const rows = panel.locator('.od-list > li');
    const count = await settledAttention(page);
    expect(count).toBeGreaterThan(0);
    const first = panel.locator('.od-dismiss').first();
    expect(await first.getAttribute('aria-label')).toMatch(/^Dismiss: /);
    await first.click();
    await expect(rows).toHaveCount(count - 1);
    await expect(page.locator('#odAttentionFoot')).toContainText('1 dismissed');
    await page.reload();
    await expect(page.locator('#overviewHostList .od-host:not(.od-skeleton)').first()).toBeVisible();
    await expect(rows).toHaveCount(count - 1);
    if (count > 2) {
        await page.locator('#odAttentionDismissAll').click();
        await expect(rows).toHaveCount(0);
    } else if (count === 2) {
        await page.locator('#odAttention .od-dismiss').first().click();
        await expect(rows).toHaveCount(0);
    }
    await expect(page.locator('#odAttentionClear')).toBeVisible();
    await expect(panel).toHaveAttribute('data-clear', 'true');
    await page.locator('#odAttentionRestore').click();
    await expect(rows).toHaveCount(count);
    await expect(page.locator('#odAttentionFoot')).toBeHidden();
});

test('a failed dismissal keeps the item and says so', async ({page}) => {
    await login(page, 'e2e_admin', {workspace: false});
    await savePreferences(page, {dismissed: []});
    await openOverview(page);
    const rows = page.locator('#odAttention .od-list > li');
    const count = await settledAttention(page);
    expect(count).toBeGreaterThan(0);
    await page.route('**/api/overview/preferences', route => route.fulfill({status: 500, json: {error: 'storage'}}));
    await page.locator('#odAttention .od-dismiss').first().click();
    await expect(page.locator('#odAttentionError')).toBeVisible();
    await expect(rows).toHaveCount(count);
});

test('the layout can be arranged by keyboard and mouse, survives reload and resets', async ({page}) => {
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.setViewportSize({width: 1600, height: 1000});
    await login(page, 'e2e_admin', {workspace: false});
    await savePreferences(page, {panels: null});
    await openOverview(page);
    await installSshConnectTrap(page);
    const order = () => page.locator('#odBoard > [data-panel]').evaluateAll(nodes => nodes
        .filter(node => node.dataset.userHidden !== 'true').sort((a, b) => Number(a.style.order) - Number(b.style.order)).map(node => node.dataset.panel));
    const defaults = ['kpis', 'topology', 'attention', 'automation', 'hosts', 'platforms', 'activity'];
    expect(await order()).toEqual(defaults);

    await page.locator('#overviewCustomize').click();
    await expect(page.locator('#overviewCustomize')).toHaveAttribute('aria-pressed', 'true');
    await expect(page.locator('#odEditBar')).toBeVisible();
    // Keyboard: move Hosts up twice, then make Activity wider.
    await page.locator('[data-panel="hosts"] [data-panel-handle]').focus();
    await page.keyboard.press('ArrowUp');
    await expect(page.locator('[data-panel="hosts"] [data-panel-handle]')).toBeFocused();
    await page.keyboard.press('ArrowUp');
    expect((await order()).slice(0, 3)).toEqual(['kpis', 'topology', 'hosts']);
    await expect(page.locator('#odLayoutStatus')).toContainText('Hosts moved to position 3');
    await page.locator('[data-panel="activity"] [data-tool="wider"]').click();
    await expect(page.locator('[data-panel="activity"]')).toHaveAttribute('data-width', '5');
    // Hide Platforms and see it offered in the tray.
    await page.getByRole('button', {name: 'Hide Platforms'}).click();
    await expect(page.locator('[data-panel="platforms"]')).toBeHidden();
    await expect(page.locator('#odHiddenPanels [data-show-panel="platforms"]')).toBeVisible();
    // Mouse: drag Activity onto Topology, resize Hosts from its corner.
    await page.locator('[data-panel="activity"] [data-panel-handle]').hover();
    await page.mouse.down();
    // Hold at the top edge until the board scrolls, then drop on Topology.
    const frame = await page.locator('#connectionOverview').boundingBox();
    await page.mouse.move(frame.x + 300, frame.y + 20, {steps: 6});
    await expect.poll(() => page.locator('#connectionOverview').evaluate(node => node.scrollTop)).toBeLessThan(5);
    const target = await page.locator('[data-panel="topology"]').boundingBox();
    await page.mouse.move(target.x + 20, target.y + Math.min(target.height / 2, 120), {steps: 8});
    await page.mouse.up();
    expect((await order()).indexOf('activity')).toBeLessThan((await order()).indexOf('topology'));
    await page.locator('[data-panel="hosts"] .od-resize').scrollIntoViewIfNeeded();
    const grip = await page.locator('[data-panel="hosts"] .od-resize').boundingBox();
    const hosts = await page.locator('[data-panel="hosts"]').boundingBox();
    await page.mouse.move(grip.x + 10, grip.y + 10);
    await page.mouse.down();
    await page.mouse.move(hosts.x + hosts.width / 2, hosts.y + 260, {steps: 6});
    await page.mouse.up();
    await expect(page.locator('[data-panel="hosts"]')).toHaveAttribute('data-fixed-height', 'true');
    const width = Number(await page.locator('[data-panel="hosts"]').getAttribute('data-width'));
    expect(width).toBeLessThan(8);
    // Panels never overlap.
    await expect.poll(() => page.locator('#odBoard > [data-panel]').evaluateAll(nodes => {
        const boxes = nodes.filter(node => node.getClientRects().length).map(node => node.getBoundingClientRect());
        return boxes.some((a, i) => boxes.slice(i + 1).some(b => Math.min(a.right, b.right) - Math.max(a.left, b.left) > 1
            && Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top) > 1));
    })).toBe(false);
    await page.keyboard.press('Escape');
    await expect(page.locator('#odEditBar')).toBeHidden();
    await expect(page.locator('#overviewCustomize')).toBeFocused();

    await expect.poll(async () => (await (await page.request.get('/')).text()).includes(`"id": "hosts", "w": ${width}`)).toBe(true);
    await page.reload();
    await expect(page.locator('#overviewHostList .od-host:not(.od-skeleton)').first()).toBeVisible();
    expect(await order()).not.toContain('platforms');
    await expect(page.locator('[data-panel="hosts"]')).toHaveAttribute('data-width', String(width));
    await expect(page.locator('[data-panel="activity"]')).toHaveAttribute('data-width', '5');

    await page.locator('#overviewCustomize').click();
    await page.locator('#odLayoutReset').click();
    await page.locator('#odLayoutDone').click();
    expect(await order()).toEqual(defaults);
    await expect.poll(async () => (await (await page.request.get('/')).text()).includes('"panels": null')).toBe(true);
    expect(await sshAttempts(page)).toEqual([]);
    expect(errors).toEqual([]);
});

test('a saved layout stacks on phones without fixed heights', async ({page}) => {
    await login(page, 'e2e_admin', {workspace: false});
    await savePreferences(page, {panels: [{id: 'hosts', w: 4, h: 30, hidden: false}, {id: 'kpis', w: 6, h: null, hidden: false}]});
    await page.setViewportSize({width: 390, height: 844});
    await openOverview(page);
    const hosts = page.locator('[data-panel="hosts"]');
    const board = await page.locator('#odBoard').boundingBox();
    const box = await hosts.boundingBox();
    expect(Math.abs(box.width - board.width)).toBeLessThan(2);
    expect(await hosts.evaluate(node => node.scrollHeight <= node.clientHeight + 1)).toBe(true);
    expect(await page.locator('#connectionOverview').evaluate(node => node.scrollWidth <= node.clientWidth + 1)).toBe(true);
    await savePreferences(page, {panels: null});
});
