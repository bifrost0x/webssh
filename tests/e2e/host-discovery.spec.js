const {test, expect} = require('playwright/test');
const {login, installSshConnectTrap, sshAttempts, assertNoExternalRequests} = require('./helpers');

// The browser suite never scans a real network: the scan API is stubbed.
async function stubScans(page, {found}) {
    const requests = [];
    let polls = 0;
    const base = {id: 'scan-1', network: '10.20.0.0/24', total: 254, blocked: 0, started_at: Date.now() / 1000};
    await page.route('**/api/discovery/scans**', async route => {
        const request = route.request();
        requests.push({method: request.method(), body: request.postDataJSON?.() || null});
        if (request.method() === 'POST') return route.fulfill({status: 202, json: {...base, state: 'running', checked: 0, found: []}});
        if (request.method() === 'DELETE') return route.fulfill({json: {...base, state: 'cancelled', checked: 40, found: []}});
        polls += 1;
        return route.fulfill({json: polls < 2 ? {...base, state: 'running', checked: 120, found: found.slice(0, 1)}
            : {...base, state: 'done', checked: 254, found}});
    });
    return requests;
}

test('discovery finds SSH endpoints and opens a prefilled new host', async ({page}, info) => {
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await login(page, 'e2e_admin', {workspace: false});
    await installSshConnectTrap(page);
    const requests = await stubScans(page, {found: [
        {address: '10.20.0.7', port: 22, name: 'nas.home.arpa', software: 'OpenSSH 9.6p1', comment: 'Ubuntu-3ubuntu13', platform: 'ubuntu', known: false},
        {address: '10.20.0.9', port: 2222, name: null, software: 'dropbear 2022.83', comment: '', platform: null, known: true},
    ]});
    await page.locator('#manageProfilesBtn').click();
    await page.locator('#findHostsBtn').click();
    const dialog = page.locator('#hostDiscoveryDialog');
    await expect(dialog).toBeVisible();
    await expect(page.locator('#hostDiscoveryNetwork')).toBeFocused();
    await expect(dialog).toContainText('The scan is not hidden');
    await page.locator('#hostDiscoveryNetwork').fill('10.20.0.0/24');
    await page.locator('#hostDiscoveryPorts').fill('22, 2222');
    await page.locator('#hostDiscoveryStart').click();
    await expect(page.locator('#hostDiscoveryCancel')).toBeVisible();
    await expect(page.locator('#hostDiscoveryResults > li')).toHaveCount(2, {timeout: 5000});
    await expect(page.locator('#hostDiscoveryProgress')).toHaveAttribute('data-state', 'done');
    await expect(page.locator('#hostDiscoveryBar')).toHaveAttribute('aria-valuenow', '100');
    await expect(page.locator('#hostDiscoveryResults > li').nth(1)).toContainText('Saved');
    expect(requests.find(item => item.method === 'POST').body).toEqual({network: '10.20.0.0/24', ports: [22, 2222]});
    await dialog.screenshot({path: info.outputPath('discovery.png'), animations: 'disabled'});

    await page.getByRole('button', {name: 'Add nas.home.arpa as a host'}).click();
    await expect(dialog).toBeHidden();
    await expect(page.locator('#profileEditorName')).toHaveValue('nas');
    await expect(page.locator('#profileEditorHost')).toHaveValue('10.20.0.7');
    await expect(page.locator('#profileEditorPort')).toHaveValue('22');
    await expect(page.locator('#profileEditorUsername')).toBeFocused();
    expect(await sshAttempts(page)).toEqual([]);
    await assertNoExternalRequests(page);
    expect(errors).toEqual([]);
});

test('discovery validates input, can be stopped and opens from the overview', async ({page}) => {
    await login(page, 'e2e_admin', {workspace: false});
    const requests = await stubScans(page, {found: []});
    await page.locator('#odBoard [data-panel="hosts"] .od-panel-head [data-host-discovery]').click();
    const dialog = page.locator('#hostDiscoveryDialog');
    await expect(dialog).toBeVisible();
    await page.locator('#hostDiscoveryNetwork').fill('');
    await page.locator('#hostDiscoveryStart').click();
    await expect(page.locator('#hostDiscoveryError')).toContainText('Enter the network');
    await page.locator('#hostDiscoveryNetwork').fill('10.20.0.0/24');
    await page.locator('#hostDiscoveryPorts').fill('22,23,24,25');
    await page.locator('#hostDiscoveryStart').click();
    await expect(page.locator('#hostDiscoveryError')).toContainText('three ports');
    expect(requests).toEqual([]);
    await page.locator('#hostDiscoveryPorts').fill('22');
    await page.locator('#hostDiscoveryStart').click();
    await page.locator('#hostDiscoveryCancel').click();
    await expect(page.locator('#hostDiscoveryState')).toHaveText('Stopped');
    await page.keyboard.press('Escape');
    await expect(dialog).toBeHidden();
});
