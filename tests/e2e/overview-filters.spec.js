const {test, expect} = require('playwright/test');
const {login, installSshConnectTrap, sshAttempts, assertNoExternalRequests} = require('./helpers');

// Readiness is stubbed so the states are known: the first three hosts wait for a host key check.
async function openWithReadiness(page) {
    // Wide enough for the drawing; narrow layouts list the routes instead.
    await page.setViewportSize({width: 1440, height: 900});
    await login(page, 'e2e_admin', {workspace: false});
    const ids = await page.evaluate(() => ProfileManager.profiles.map(profile => profile.id));
    expect(ids.length).toBeGreaterThan(4);
    const pending = ids.slice(0, 3);
    await page.route('**/api/overview/status', route => route.fulfill({json: {hosts: ids.map(id => pending.includes(id)
        ? {id, state: 'action', host_key: 'unknown'} : {id, state: 'ready'})}}));
    await page.goto('/');
    await expect(page.locator('#overviewHostList .od-host:not(.od-skeleton)').first()).toBeVisible();
    await expect(page.locator('#overviewHostList .od-host[data-state="unknown"]')).toHaveCount(0);
    await installSshConnectTrap(page);
    return {ids, pending};
}

test('state filters, node focus and a click on empty space shape the drawing and the cards together', async ({page}) => {
    const {ids, pending} = await openWithReadiness(page);
    const cards = page.locator('#overviewHostList .od-host');
    const action = page.locator('.od-legend-filter[data-state="action"]');
    await expect(action.locator('.od-legend-count')).toHaveText(String(pending.length));
    await action.click();
    await expect(action).toHaveAttribute('aria-pressed', 'true');
    await expect(cards).toHaveCount(pending.length);
    await expect(page.locator('#overviewHostTotal')).toHaveText(`${pending.length} / ${ids.length}`);
    // The drawing may fold some hosts into "+n"; whatever it still highlights has the chosen state.
    await expect(page.locator('#odTopology .od-node[data-dim="false"]:not([data-state="action"])')).toHaveCount(0);
    await expect(page.locator('#odTopology .od-node[data-dim="true"]').first()).toBeAttached();
    await action.click();
    await expect(action).toHaveAttribute('aria-pressed', 'false');
    await expect(cards).toHaveCount(ids.length);

    // A node focuses exactly its host, then empty space brings everything back.
    await page.locator('.od-legend-filter[data-state="ready"]').click();
    await page.locator('#odTopology .od-node').first().click();
    await expect(cards).toHaveCount(1);
    await expect(page.locator('.od-legend-filter[aria-pressed="true"]')).toHaveCount(0);
    const box = await page.locator('#odTopology').boundingBox();
    await page.mouse.click(box.x + 8, box.y + 8);
    await expect(cards).toHaveCount(ids.length);
    await expect(page.locator('#overviewSearch')).toHaveValue('');

    // The WebSSH core resets as well.
    await page.locator('#odTopology .od-node').first().click();
    await expect(cards).toHaveCount(1);
    // The core's ring turns continuously, so it never counts as "stable" for a normal click.
    await page.locator('#odTopology .od-core').click({force: true});
    await expect(cards).toHaveCount(ids.length);
    expect(await sshAttempts(page)).toEqual([]);
    await assertNoExternalRequests(page);
});

test('the status pill and grouped attention items lead to exactly the affected hosts', async ({page}) => {
    const {ids, pending} = await openWithReadiness(page);
    // The pill counts the hosts an item covers, like the host tile does, not the number of rows.
    const rows = page.locator('#odAttention .od-row');
    const covered = await page.evaluate(() => window.overviewWorkspace && document.querySelectorAll('#odAttention .od-row').length);
    expect(covered).toBeGreaterThan(0);
    const status = await page.locator('#overviewStatusText').textContent();
    expect(Number(status.match(/\d+/)?.[0])).toBeGreaterThanOrEqual(pending.length);
    const pill = page.locator('#overviewStatusButton');
    await expect(pill).toBeEnabled();
    await pill.click();
    await expect(rows.first()).toBeFocused();
    await page.locator('#odAttention .od-row[data-kind="host-keys"]').click();
    const cards = page.locator('#overviewHostList .od-host');
    await expect(cards).toHaveCount(pending.length);
    expect(await cards.evaluateAll(nodes => nodes.map(node => node.dataset.hostId).sort())).toEqual([...pending].sort());
    const chip = page.locator('#overviewHostFilter');
    await expect(chip).toBeVisible();
    await expect(chip).toContainText('Host key not verified');
    await chip.click();
    await expect(chip).toBeHidden();
    await expect(cards).toHaveCount(ids.length);
    expect(await sshAttempts(page)).toEqual([]);
});

test('discovery returns after the editor, keeps added hosts marked and passes the greeting platform', async ({page}) => {
    await login(page, 'e2e_admin', {workspace: false});
    const found = [
        {address: '10.20.0.31', port: 22, name: null, software: 'OpenSSH 9.2p1', comment: 'Debian-2+deb12u3', platform: 'debian', known: false},
        {address: '10.20.0.32', port: 22, name: null, software: 'OpenSSH 9.6p1', comment: 'Ubuntu-3ubuntu13.5', platform: 'ubuntu', known: false},
    ];
    // The scan keeps reporting its start-time view, as a long scan does.
    await page.route('**/api/discovery/scans**', route => route.fulfill({status: route.request().method() === 'POST' ? 202 : 200,
        json: {id: 'scan-ret', network: '10.20.0.0/24', state: 'running', total: 254, checked: 200, blocked: 0, found}}));
    let profileId = null;
    try {
        await page.locator('#manageProfilesBtn').click();
        await page.locator('#findHostsBtn').click();
        const dialog = page.locator('#hostDiscoveryDialog');
        await page.locator('#hostDiscoveryNetwork').fill('10.20.0.0/24');
        await page.locator('#hostDiscoveryStart').click();
        await expect(page.locator('#hostDiscoveryResults > li')).toHaveCount(2);

        // Leaving the editor without saving returns to the results.
        await page.getByRole('button', {name: 'Add 10.20.0.31 as a host'}).click();
        await expect(dialog).toBeHidden();
        await page.locator('#profileEditorView .profile-inspector-close').click();
        // The prefilled form counts as a change, so leaving asks first.
        await page.locator('.command-set-confirm-dialog').getByRole('button', {name: 'Discard', exact: true}).click();
        await expect(dialog).toBeVisible();
        await expect(page.getByRole('button', {name: 'Add 10.20.0.31 as a host'})).toBeVisible();

        // Saving returns as well; the host stays marked while the scan still runs.
        await page.getByRole('button', {name: 'Add 10.20.0.31 as a host'}).click();
        await page.locator('#profileEditorUsername').fill('ops');
        await page.locator('#profileEditorForm').getByRole('button', {name: 'Save', exact: true}).click();
        await expect(dialog).toBeVisible();
        await expect(page.locator('#hostDiscoveryResults > li').first()).toContainText('Saved');
        await expect(page.getByRole('button', {name: 'Add 10.20.0.32 as a host'})).toBeFocused();
        await page.waitForTimeout(1200);
        await expect(page.locator('#hostDiscoveryResults > li').first()).toContainText('Saved');
        await page.locator('#hostDiscoveryClose').click();

        const saved = await page.evaluate(() => ProfileManager.profiles.find(profile => profile.host === '10.20.0.31'));
        profileId = saved.id;
        expect(saved.greeting_platform).toBe('debian');
        const icon = page.locator(`.profile-inspect-button[data-profile-id="${profileId}"] .host-platform-icon, [data-profile-id="${profileId}"] .host-platform-icon`).first();
        await expect(icon).toHaveAttribute('data-platform', 'debian');
        await expect(icon).toHaveAttribute('title', /SSH greeting/);
    } finally {
        if (profileId) await page.evaluate(id => new Promise(resolve => window.socket.emit('delete_profile', {profile_id: id}, resolve)), profileId);
    }
    expect(await sshAttempts(page)).toEqual([]);
});
