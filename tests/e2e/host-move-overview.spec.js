const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');
// The overview move menu lives in the classic overview layout.
const layout = async (page, value) => {
    const response = await page.request.post('/api/account/preferences', {data:{overview_layout:value}, headers:{'X-CSRFToken':await page.locator('meta[name="csrf-token"]').getAttribute('content')}});
    expect(response.ok()).toBe(true);
};
async function classicLogin(page) {
    await login(page, 'e2e_admin', {workspace:false});
    await layout(page, 'classic');
    await page.goto('/');
    await expect.poll(() => page.evaluate(() => window.ProfileManager?.profilesLoaded === true && window.JumpHostManager?.loaded === true)).toBe(true);
    await expect(page.locator('#overviewHostSearch')).toBeVisible();
}
test.afterEach(async ({page}) => { await layout(page, 'dashboard'); });
for (const graph of [false, true]) {
    test(`Overview ${graph ? 'routes' : 'inventory'} moves hosts through the existing organization contract`, async ({page}) => {
        await classicLogin(page);
        await page.evaluate(() => {
            const template = window.ProfileManager.profiles[0];
            window.ProfileManager.setProfiles([
                {...template, id:'move-a', name:'Move A', group:'Source', favorite:false},
                {...template, id:'move-b', name:'Move B', group:'Target', favorite:false},
            ]);
            const original = window.socket.emit.bind(window.socket);
            window.__moves = []; window.__ssh = [];
            window.socket.emit = (event, ...args) => {
                const [payload, ack] = args;
                if (event === 'list_profiles') {
                    queueMicrotask(() => window.socket.listeners('profiles_list').forEach(listener => listener({profiles: window.ProfileManager.profiles})));
                    return window.socket;
                }
                if (event === 'ssh_connect') { window.__ssh.push(payload); return; }
                if (event !== 'move_profile') return original(event, ...args);
                window.__moves.push(payload);
                ack({success:true, organization:[{id:payload.profile_id, group:payload.target_group, sort_order:payload.target_index}]});
            };
        });
        await expect(page.locator('#overviewHosts .overview-host-group')).toHaveCount(2);
        await page.locator('#overviewGroupFilter').selectOption('group:Source');
        if (graph) {
            await page.locator('#overviewGraphBtn').click();
            await expect(page.locator('#overviewGraphBtn')).toHaveAttribute('aria-pressed', 'true');
        }
        const host = page.locator('#overviewHosts [data-host-id="move-a"]');
        await expect(host).toBeVisible();
        let row = page.locator('#overviewHosts .overview-host-entry').filter({has: page.locator('[data-host-id="move-a"]')});
        await row.locator('summary').click();
        await expect(row.locator('option')).toHaveCount(3);
        await row.locator('select').selectOption('Target');
        await expect.poll(() => page.evaluate(() => window.__moves.length)).toBe(1);
        expect(await page.evaluate(() => window.__moves[0])).toEqual({profile_id:'move-a',expected_source_group:'Source',target_group:'Target',target_index:1,confirm_source_group_removal:false});
        await expect(page.locator('#overviewHosts [data-host-drop-group="Target"] [data-host-id="move-a"]')).toBeVisible();
        row = page.locator('#overviewHosts .overview-host-entry').filter({has: page.locator('[data-host-id="move-a"]')});
        await expect(row.locator('summary')).toBeFocused();
        await row.locator('summary').click();
        await row.locator('select').selectOption('');
        await expect.poll(() => page.evaluate(() => window.__moves.length)).toBe(2);
        expect(await page.evaluate(() => window.__moves[1])).toEqual({profile_id:'move-a',expected_source_group:'Target',target_group:'',target_index:0,confirm_source_group_removal:false});
        await expect(page.locator('#overviewHosts [data-host-drop-group=""] [data-host-id="move-a"]')).toBeVisible();
        await expect(row.locator('summary')).toBeFocused();
        await row.locator('summary').press('Enter');
        await expect(row.locator('select')).toBeVisible();
        await row.locator('select').press('Escape');
        await expect(row.locator('select')).toBeHidden();
        await expect(row.locator('summary')).toBeFocused();
        if (!graph) {
            // A favorite can be moved onto a collapsed Hosts group too.
            await page.evaluate(() => window.ProfileManager.setProfiles(
                window.ProfileManager.profiles.map(profile => profile.id === 'move-a'
                    ? {...profile, favorite:true} : profile),
            ));
            await page.locator('#manageProfilesBtn').click();
            await page.locator('[data-profile-group-toggle="group:target"]').click();
            const favorite = page.locator('[data-profile-card-id="move-a"] [data-profile-drag-handle]');
            await expect(favorite).toBeEnabled();
            await favorite.dragTo(page.locator('.profile-management-section-title[data-profile-drop-group="Target"]'));
            await expect.poll(() => page.evaluate(() => window.__moves.length)).toBe(3);
            expect(await page.evaluate(() => window.ProfileManager.profiles.find(p => p.id === 'move-a').group)).toBe('Target');
        }
        expect(await page.evaluate(() => window.__ssh)).toEqual([]);
        await assertNoExternalRequests(page);
    });
}

test('large host stores populate only the open move menu', async ({page}) => {
    await classicLogin(page);
    await page.evaluate(() => {
        const template = window.ProfileManager.profiles[0];
        window.ProfileManager.setProfiles(Array.from({length:500}, (_, i) => ({
            ...template, id:`large-${i}`, name:`Host ${i}`, group:`Group ${i}`, favorite:false,
        })));
    });
    await expect(page.locator('#overviewHostCount')).toHaveText('500');
    await expect(page.locator('#overviewHosts .overview-host-group')).toHaveCount(500);
    await expect(page.locator('#overviewHosts .overview-host-entry')).toHaveCount(500);
    await expect(page.locator('.overview-host-move option')).toHaveCount(0);
    await page.locator('#overviewGroupFilter').selectOption('group:Group 0');
    const rows = page.locator('#overviewHosts .overview-host-entry');
    await expect(rows).toHaveCount(1);
    await expect(page.locator('.overview-host-move option')).toHaveCount(0);
    await rows.first().locator('summary').click();
    await expect(rows.first().locator('option')).toHaveCount(501);
    await expect(page.locator('.overview-host-move option')).toHaveCount(501);
    await rows.first().locator('select').press('Escape');
    await expect(page.locator('.overview-host-move option')).toHaveCount(0);
    await assertNoExternalRequests(page);
});
