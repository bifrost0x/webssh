const {test, expect} = require('playwright/test');
const {login, waitForInventory, installSshConnectTrap, sshAttempts, assertNoExternalRequests} = require('./helpers');

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
    await waitForInventory(page);
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
    await page.locator('#odTopology').click({position: {x: 8, y: 8}});
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
    await expect.poll(async () => Number((await page.locator('#overviewStatusText').textContent()).match(/\d+/)?.[0])).toBeGreaterThanOrEqual(pending.length);
    const pill = page.locator('#overviewStatusButton');
    await expect(pill).toBeEnabled();
    // With the list already on screen, the click must still answer visibly.
    await page.locator('#odAttention').scrollIntoViewIfNeeded();
    await pill.click();
    await expect(rows.first()).toBeFocused();
    await expect(page.locator('#odAttention')).toHaveClass(/od-panel-flash/);
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

test('detected services show on host cards and filter the overview from the platforms panel', async ({page}) => {
    const {ids} = await openWithReadiness(page);
    await page.evaluate(([first, second]) => {
        ProfileManager.setProfiles(ProfileManager.profiles.map(profile => profile.id === first
            ? {...profile, detected_services: ['docker', 'nextcloud', 'nginx', 'postgresql', 'grafana']}
            : profile.id === second ? {...profile, detected_services: ['docker']} : profile));
    }, ids);
    const card = page.locator(`#overviewHostList .od-host[data-host-id="${ids[0]}"]`);
    await expect(card.locator('.od-service-chip')).toHaveText(['Docker', 'Nextcloud', 'nginx', '+2']);
    await expect(card.locator('.od-service-chip').last()).toHaveAttribute('title', 'PostgreSQL, Grafana');
    const docker = page.locator('#odPlatforms .od-service[data-service="docker"]');
    await expect(docker.locator('.od-count')).toHaveText('2');
    await docker.click();
    await expect(page.locator('#overviewHostList .od-host')).toHaveCount(2);
    await expect(page.locator('#overviewHostFilter')).toContainText('Docker');
    await page.locator('#overviewHostFilter').click();
    await expect(page.locator('#overviewHostList .od-host')).toHaveCount(ids.length);
});

test('restart and security update facts appear on host cards and lead to the affected hosts', async ({page}) => {
    const {ids} = await openWithReadiness(page);
    const [restart, updates] = ids.slice(-2);
    await page.evaluate(([restartId, updatesId]) => {
        const checked = Math.floor(Date.now() / 1000);
        ProfileManager.profiles.forEach(profile => {
            if (profile.id === restartId) profile.detected_maintenance = {reboot_required: true, updates: 0, security_updates: 0, checked_at: checked};
            if (profile.id === updatesId) profile.detected_maintenance = {reboot_required: false, updates: 7, security_updates: 2, checked_at: checked};
        });
        window.dispatchEvent(new Event('profile-list-change'));
    }, [restart, updates]);
    const restartCard = page.locator(`#overviewHostList .od-host[data-host-id="${restart}"]`);
    await expect(restartCard.locator('.od-maintenance-chip[data-kind="reboot"]')).toHaveText(/Restart required/);
    const updatesCard = page.locator(`#overviewHostList .od-host[data-host-id="${updates}"]`);
    await expect(updatesCard.locator('.od-maintenance-chip[data-kind="security"]')).toHaveText(/7 updates, 2 security/);
    await expect(updatesCard.locator('.od-maintenance-chip')).toHaveAttribute('title', /package cache/);
    const row = page.locator('#odAttention .od-row[data-kind="security-updates"]');
    await expect(row).toBeVisible();
    await row.click();
    await expect(page.locator(`#overviewHostList .od-host[data-host-id="${updates}"]`)).toBeVisible();
    await expect(page.locator('#odAttention .od-row[data-kind="reboot"]')).toBeVisible();
    expect(await sshAttempts(page)).toEqual([]);
});

test('pending security updates open the matching upgrade workflow as a draft with exactly those hosts', async ({page}) => {
    const {ids} = await openWithReadiness(page);
    await expect.poll(() => page.evaluate(() => window.WebSSHAutomation?.getRunSnapshot?.().enabled === true)).toBe(true);
    const affected = ids.slice(-2);
    await page.evaluate(hostIds => {
        const checked = Math.floor(Date.now() / 1000);
        ProfileManager.profiles.forEach(profile => {
            if (hostIds.includes(profile.id)) Object.assign(profile, {detected_platform: 'debian',
                detected_maintenance: {reboot_required: false, updates: 3, security_updates: 1, checked_at: checked}});
        });
        window.dispatchEvent(new Event('profile-list-change'));
    }, affected);
    const writes = [];
    page.on('request', request => { if (request.method() !== 'GET' && request.url().includes('/api/automation/')) writes.push(request.url()); });
    const open = page.locator('#odAttention [data-key^="upgrade:"]');
    await expect(open).toBeVisible();
    await expect(open).toHaveAttribute('aria-label', 'Open upgrade workflow for 2 hosts');
    await open.click();
    await expect(page.locator('#runbookName')).toHaveValue('Debian / Ubuntu package upgrade');
    await expect.poll(() => page.locator('#targetHosts input:checked').evaluateAll(inputs => inputs.map(input => input.value).sort()))
        .toEqual([...affected].sort());
    await expect(page.locator('#saveState')).not.toHaveText('');
    expect(writes).toEqual([]);
    expect(await sshAttempts(page)).toEqual([]);
});

test('a restart hint offers to check the same hosts again, as a draft and without contacting them', async ({page}) => {
    const {ids} = await openWithReadiness(page);
    await expect.poll(() => page.evaluate(() => window.WebSSHAutomation?.getRunSnapshot?.().enabled === true)).toBe(true);
    const affected = ids.slice(-2);
    await page.evaluate(hostIds => {
        const checked = Math.floor(Date.now() / 1000);
        ProfileManager.profiles.forEach(profile => {
            if (hostIds.includes(profile.id)) profile.detected_maintenance = {reboot_required: true, checked_at: checked};
        });
        window.dispatchEvent(new Event('profile-list-change'));
    }, affected);
    const writes = [];
    page.on('request', request => { if (request.method() !== 'GET' && request.url().includes('/api/automation/')) writes.push(request.url()); });
    const recheck = page.locator('#odAttention [data-key^="recheck:"]');
    await expect(recheck).toHaveAttribute('aria-label', 'Check restart status again for 2 hosts');
    await recheck.click();
    await expect(page.locator('#runbookName')).toHaveValue('Updates and restart status');
    await expect.poll(() => page.locator('#targetHosts input:checked').evaluateAll(inputs => inputs.map(input => input.value).sort()))
        .toEqual([...affected].sort());
    expect(writes).toEqual([]);
    expect(await sshAttempts(page)).toEqual([]);
});
