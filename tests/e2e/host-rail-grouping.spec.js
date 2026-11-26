const {test, expect} = require('playwright/test');
const {login, openWorkspace, installSshConnectTrap, sshAttempts} = require('./helpers');

const KEY = 'webssh.hostRailGrouping';
const profiles = [
    {id: 'p1', name: 'pve-one', group: 'Lab', role_override: 'hypervisor', favorite: true},
    {id: 'p2', name: 'nas-one', group: 'Lab', role_override: 'storage'},
    {id: 'p3', name: 'pve-two', group: 'Edge', role_override: 'hypervisor'},
    {id: 'p4', name: 'plain', group: 'Edge', favorite: true,
        detected_services: ['docker', 'grafana', 'prometheus', 'nginx', 'redis', 'loki']},
    {id: 'p5', name: 'a-rather-long-host-name-for-a-narrow-rail', group: 'Edge', role_override: 'media',
        detected_services: ['jellyfin', 'sonarr', 'radarr', 'prowlarr']},
].map(profile => ({host: `${profile.id}.example.invalid`, port: 22, username: 'demo', auth_type: 'password', ...profile}));

async function openRail(page) {
    await page.evaluate(items => {
        ProfileManager.setProfiles(items);
        SessionManager.createSession({session_id: 'rail-test', host: 'fixture.example.invalid', username: 'demo', port: 22});
    }, profiles);
    if (await page.locator('#toggleHostRail').getAttribute('aria-expanded') !== 'true') await page.locator('#toggleHostRail').click();
    await expect(page.locator('#shellGroups .shell-host').first()).toBeVisible();
}
const headings = page => page.locator('#shellGroups > details > summary > span:not(.material-icons)').allTextContents();
const hosts = page => page.locator('#shellGroups .shell-host').evaluateAll(items => items.map(item => item.getAttribute('aria-label')));

test.beforeEach(async ({page}) => {
    await page.setViewportSize({width: 1440, height: 900});
    await login(page);
    await installSshConnectTrap(page);
});

test('the rail groups by group until the role mode is chosen, and remembers the choice', async ({page}) => {
    await openRail(page);
    const radios = page.locator('.shell-grouping [role="radio"]');
    await expect(page.locator('.shell-grouping')).toHaveAttribute('role', 'radiogroup');
    await expect(radios).toHaveCount(2);
    await expect(radios.nth(0)).toHaveAttribute('aria-checked', 'true');
    expect(await headings(page)).toEqual(['Edge', 'Lab']);
    expect(await hosts(page)).toEqual(['a-rather-long-host-name-for-a-narrow-rail', 'plain', 'pve-two', 'nas-one', 'pve-one']);

    await radios.nth(1).click();
    await expect(radios.nth(1)).toHaveAttribute('aria-checked', 'true');
    expect(await headings(page)).toEqual(['Hypervisor', 'Storage', 'Media', 'Monitoring']);
    await expect(page.locator('#shellGroups > details[data-role="hypervisor"] .shell-host')).toHaveCount(2);
    await expect(page.locator('#shellGroups > details[data-role="media"] .shell-host[data-role="media"]')).toHaveCount(1);
    expect(await page.evaluate(key => localStorage.getItem(key), KEY)).toBe('role');

    await page.reload();
    await openWorkspace(page);
    await openRail(page);
    await expect(page.locator('.shell-grouping [data-grouping="role"]')).toHaveAttribute('aria-checked', 'true');
    expect(await headings(page)).toEqual(['Hypervisor', 'Storage', 'Media', 'Monitoring']);
    expect(await sshAttempts(page)).toEqual([]);
});

test('an invalid stored value falls back to the group mode', async ({page}) => {
    await page.evaluate(key => localStorage.setItem(key, 'sideways'), KEY);
    await page.reload();
    await openWorkspace(page);
    await openRail(page);
    await expect(page.locator('.shell-grouping [data-grouping="group"]')).toHaveAttribute('aria-checked', 'true');
    expect(await headings(page)).toEqual(['Edge', 'Lab']);
});

test('arrow keys move through the radio group and the favourites filter applies in both modes', async ({page}) => {
    await openRail(page);
    const group = page.locator('.shell-grouping [data-grouping="group"]');
    const role = page.locator('.shell-grouping [data-grouping="role"]');
    await group.focus();
    await page.keyboard.press('ArrowRight');
    await expect(role).toBeFocused();
    await expect(role).toHaveAttribute('aria-checked', 'true');
    await expect(group).toHaveAttribute('tabindex', '-1');
    await page.keyboard.press('ArrowRight');
    await expect(group).toBeFocused();
    await expect(group).toHaveAttribute('aria-checked', 'true');
    await page.keyboard.press('ArrowLeft');
    await expect(role).toBeFocused();

    await page.evaluate(() => { document.body.dataset.hostAccessFilter = 'favorites'; window.dispatchEvent(new Event('host-access-change')); });
    expect(await headings(page)).toEqual(['Hypervisor', 'Monitoring']);
    expect(await hosts(page)).toEqual(['pve-one', 'plain']);
    await group.click();
    expect(await headings(page)).toEqual(['Edge', 'Lab']);
    expect(await hosts(page)).toEqual(['plain', 'pve-one']);
});

test('collapsing a heading in one mode leaves the other mode open', async ({page}) => {
    await openRail(page);
    await page.locator('#shellGroups > details').first().locator('summary').click();
    await expect(page.locator('#shellGroups > details').first()).not.toHaveAttribute('open', '');
    await page.locator('.shell-grouping [data-grouping="role"]').click();
    await expect(page.locator('#shellGroups > details:not([open])')).toHaveCount(0);
    await page.locator('#shellGroups > details').first().locator('summary').click();
    await page.locator('.shell-grouping [data-grouping="group"]').click();
    await expect(page.locator('#shellGroups > details:not([open])')).toHaveCount(1);
    await expect(page.locator('#shellGroups > details').first()).not.toHaveAttribute('open', '');
});

test('rows show at most four service logos and drop them before cutting a name', async ({page}) => {
    await openRail(page);
    const crowded = page.locator('#shellGroups .shell-host[aria-label="plain"]');
    const tiles = crowded.locator('.shell-host-service:visible');
    expect(await tiles.count()).toBeLessThanOrEqual(4);
    const long = page.locator('#shellGroups .shell-host[aria-label^="a-rather-long"]');
    const logos = await long.evaluate(row => row.querySelectorAll('.shell-host-service:not([hidden])').length);
    // The name alone is wider than the rail: logos may not take any of its room.
    expect(logos).toBe(0);
});

test('names are text only and the rail does not overflow on a narrow screen', async ({page}) => {
    await page.setViewportSize({width: 360, height: 740});
    await page.evaluate(items => {
        ProfileManager.setProfiles([...items, {id: 'x', name: '<img src=x onerror=window.__pwn=1>', group: '<b>g</b>', host: 'x.example.invalid', port: 22, username: 'demo', auth_type: 'password'}]);
        SessionManager.createSession({session_id: 'rail-test', host: 'fixture.example.invalid', username: 'demo', port: 22});
    }, profiles);
    if (await page.locator('#toggleHostRail').isVisible()) await page.locator('#toggleHostRail').click();
    const heading = page.locator('.shell-groups-heading');
    if (await heading.isVisible()) {
        const box = await page.locator('#shellHostAccess').evaluate(rail => ({scroll: rail.scrollWidth, client: rail.clientWidth}));
        expect(box.scroll).toBeLessThanOrEqual(box.client);
        const inside = await page.locator('.shell-grouping').evaluate(item => {
            const rail = item.closest('#shellHostAccess').getBoundingClientRect();
            const rect = item.getBoundingClientRect();
            return rect.left >= rail.left && rect.right <= rail.right;
        });
        expect(inside).toBe(true);
    }
    expect(await page.evaluate(() => window.__pwn)).toBeUndefined();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});
