const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests, installSshConnectTrap} = require('./helpers');

async function fixtures(page) {
    await page.evaluate(() => {
        JumpHostManager.setJumpHosts([{id:'arrange-jump',name:'Bastion'}]);
        ProfileManager.setProfiles([
            {id:'alpha',name:'Alpha host',group:'Alpha'},
            ...Array.from({length:3},(_,i) => ({id:`beta-${i}`,name:`Beta host ${i}`,group:'Beta'})),
            {id:'gamma',name:'Gamma host',group:'Gamma'},
        ]);
    });
}
const groups = page => page.locator('#overviewHosts .overview-host-group');
const order = page => groups(page).evaluateAll(cards => cards.map(card => card.dataset.hostDropGroup));
const card = (page, name) => page.locator(`#overviewHosts [data-host-drop-group="${name}"]`);

for (const width of [1440, 870, 390]) {
    test(`group arrangement is compact, accessible and persistent at ${width}px`, async ({page}) => {
        await page.setViewportSize({width,height:900});
        await login(page, 'e2e_admin', {workspace:false});
        await fixtures(page);
        await installSshConnectTrap(page);
        await page.locator('#overviewGraphBtn').click();
        await expect(groups(page)).toHaveCount(3);
        if (width === 870) {
            await expect.poll(async () => {
                const a = await card(page,'Alpha').boundingBox();
                const b = await card(page,'Beta').boundingBox();
                const c = await card(page,'Gamma').boundingBox();
                return c.y < b.y + b.height && c.y >= a.y + a.height;
            }).toBe(true);
        }
        await page.locator('#overviewArrangeGroups').click();
        await expect(page.locator('#overviewArrangePanel')).toBeVisible();
        await card(page,'Gamma').locator('input').fill('1');
        await card(page,'Gamma').locator('input').press('Enter');
        await expect.poll(() => order(page)).toEqual(['Gamma','Alpha','Beta']);
        await expect(card(page,'Gamma').locator('input')).toBeFocused();
        await expect(page.locator('#overviewArrangeStatus')).toContainText('saved');
        if (width === 1440) {
            await card(page,'Beta').locator('.overview-group-drag').dragTo(card(page,'Gamma'));
            await expect.poll(() => order(page)).toEqual(['Beta','Gamma','Alpha']);
        }
        const expected = await order(page);
        await page.locator('#overviewListBtn').click();
        await expect.poll(() => order(page)).toEqual(expected);
        await page.locator('#overviewHostSearch').fill('Gamma');
        await expect.poll(() => order(page)).toEqual(['Gamma']);
        await page.locator('#overviewHostSearch').fill('');
        await expect.poll(() => order(page)).toEqual(expected);
        await page.reload();
        await expect.poll(() => page.evaluate(() => ProfileManager.profilesLoaded)).toBe(true);
        await fixtures(page);
        await expect.poll(() => order(page)).toEqual(expected);
        await page.locator('#overviewArrangeGroups').click();
        await page.locator('#overviewSortGroupsDesc').click();
        await expect.poll(() => order(page)).toEqual(['Gamma','Beta','Alpha']);
        await page.locator('#overviewSortGroupsAsc').click();
        await expect.poll(() => order(page)).toEqual(['Alpha','Beta','Gamma']);
        await page.locator('#overviewArrangeGroups').click();
        await expect(page.locator('.overview-group-controls')).toHaveCount(0);
        expect(await page.locator('#connectionOverview').evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true);
        await assertNoExternalRequests(page);
    });
}

test('reordering preserves exact route assignments, host membership and session state', async ({page}) => {
    await page.setViewportSize({width:1440,height:1000});
    await login(page, 'e2e_admin', {workspace:false});
    await fixtures(page);
    await page.evaluate(() => ProfileManager.setProfiles(ProfileManager.profiles.map(p => ({...p,jump_host_id:'arrange-jump'}))));
    await installSshConnectTrap(page);
    const before = await page.evaluate(() => JSON.stringify(ProfileManager.profiles));
    await page.locator('#overviewGraphBtn').click();
    await expect(page.locator('#overviewHosts .overview-edges path')).toHaveCount(5);
    await page.locator('#overviewArrangeGroups').click();
    await card(page,'Gamma').locator('.overview-group-drag').dragTo(card(page,'Alpha').locator('.overview-group-drag'));
    await expect.poll(() => order(page)).toEqual(['Gamma','Alpha','Beta']);
    expect(await page.locator('#overviewHosts .overview-edges path').evaluateAll(paths => paths.map(p => [p.dataset.sourceId,p.dataset.targetId]).sort())).toEqual(
        ['alpha','beta-0','beta-1','beta-2','gamma'].map(id => ['arrange-jump',id]),
    );
    expect(await page.evaluate(() => JSON.stringify(ProfileManager.profiles))).toBe(before);
    expect(await page.evaluate(() => window.__sshConnectAttempts)).toEqual([]);
    // A changed account scope does not inherit this account's saved order.
    await page.route('**/', async route => {
        const response = await route.fetch();
        const body = (await response.text()).replace(/name="background-scope" content="[a-f0-9]{64}"/, `name="background-scope" content="${'b'.repeat(64)}"`);
        await route.fulfill({response,body});
    });
    await page.reload();
    await expect.poll(() => page.evaluate(() => ProfileManager.profilesLoaded)).toBe(true);
    await fixtures(page);
    await expect.poll(() => order(page)).toEqual(['Alpha','Beta','Gamma']);
    await assertNoExternalRequests(page);
});

test('unavailable browser storage keeps arrangement usable and reports it honestly', async ({page}) => {
    await login(page,'e2e_admin',{workspace:false});
    await fixtures(page);
    await page.evaluate(() => {
        const original = Storage.prototype.setItem;
        Storage.prototype.setItem = function(key,value) {
            if (key.startsWith('webssh:overview-group-order:')) throw new DOMException('Blocked','QuotaExceededError');
            return original.call(this,key,value);
        };
    });
    await page.locator('#overviewArrangeGroups').click();
    await page.locator('#overviewSortGroupsDesc').click();
    await expect.poll(() => order(page)).toEqual(['Gamma','Beta','Alpha']);
    await expect(page.locator('#overviewArrangeStatus')).toContainText('could not be saved');
    await card(page,'Alpha').locator('input').fill('999');
    await card(page,'Alpha').locator('input').press('Enter');
    await expect.poll(() => order(page)).toEqual(['Gamma','Beta','Alpha']);
    await assertNoExternalRequests(page);
});

test('arrangement controls support every language/theme, large stores and empty results', async ({page}) => {
    await page.setViewportSize({width:390,height:844});
    const errors=[];
    page.on('pageerror', error => errors.push(error.message));
    await login(page,'e2e_admin',{workspace:false});
    await fixtures(page);
    await page.locator('#overviewGraphBtn').click();
    await page.locator('#overviewArrangeGroups').click();
    for (const [language,label] of Object.entries({en:'Arrange groups',de:'Gruppen anordnen',vi:'Sắp xếp nhóm',fr:'Organiser les groupes',es:'Organizar grupos',zh:'排列分组'})) {
        await page.evaluate(lang => i18n.setLanguage(lang),language);
        await expect(page.locator('#overviewArrangeGroups')).toContainText(label);
        expect(await page.locator('#overviewArrangePanel').evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true);
    }
    for (const theme of ['glass','solar','paper','noir','arctic-ice','rose-gold','obsidian','retro','cyberpunk-neon','emerald-matrix']) {
        await page.evaluate(theme => document.body.dataset.theme=theme,theme);
        const colors = await card(page,'Alpha').locator('input').evaluate(el => ({color:getComputedStyle(el).color,background:getComputedStyle(el).backgroundColor}));
        expect(colors.color).not.toBe(colors.background);
        expect(await page.locator('#connectionOverview').evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true);
    }
    await page.locator('#overviewListBtn').click();
    await page.locator('#overviewHostSearch').fill('no such host');
    await expect(page.locator('#overviewHosts')).not.toHaveClass(/overview-group-layout/);
    const empty = await page.locator('#overviewHosts .overview-empty').boundingBox();
    const container = await page.locator('#overviewHosts').boundingBox();
    expect(container.height).toBeGreaterThanOrEqual(empty.height);
    await page.locator('#overviewHostSearch').fill('');
    await page.evaluate(() => ProfileManager.setProfiles(Array.from({length:500},(_,i) => ({id:`group-${i}`,name:`Host ${i}`,group:`Group ${i}`}))));
    await expect(page.locator('#overviewHosts .overview-group-controls')).toHaveCount(500);
    await page.locator('#overviewSortGroupsDesc').click();
    expect((await order(page)).length).toBe(500);
    await expect.poll(() => groups(page).evaluateAll(cards => {
        const rects=cards.map(card => card.getBoundingClientRect());
        return rects.every((rect,i) => !i || rect.top >= rects[i-1].bottom);
    })).toBe(true);
    await expect(page.locator('.overview-host-move option')).toHaveCount(0);
    await page.locator('#overviewGroupFilter').selectOption('group:Group 1');
    await expect(groups(page)).toHaveCount(1);
    expect(errors).toEqual([]);
    await assertNoExternalRequests(page);
});
