const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests, installSshConnectTrap} = require('./helpers');

// Group arrangement lives in the classic overview layout.
const setLayout = async (page, value) => {
    const response = await page.request.post('/api/account/preferences', {data:{overview_layout:value}, headers:{'X-CSRFToken':await page.locator('meta[name="csrf-token"]').getAttribute('content')}});
    expect(response.ok()).toBe(true);
};
let classic = false;
async function openClassic(page) {
    await setLayout(page, 'classic');
    classic = true;
    await page.reload();
    await expect(page.locator('#overviewArrangeGroups')).toBeVisible();
}
test.afterEach(async ({page}) => {
    if (!classic) return;
    classic = false;
    await setLayout(page, 'dashboard');
});

async function fixtures(page) {
    await expect.poll(() => page.evaluate(() => window.ProfileManager?.profilesLoaded && window.JumpHostManager?.loaded)).toBe(true);
    await page.evaluate(() => {
        JumpHostManager.setJumpHosts([{id:'arrange-jump',name:'Bastion'}]);
        ProfileManager.setProfiles([
            {id:'alpha',name:'Alpha host',group:'Alpha'},
            ...Array.from({length:3},(_,i) => ({id:`beta-${i}`,name:`Beta host ${i}`,group:'Beta'})),
            {id:'gamma',name:'Gamma host',group:'Gamma'},
        ]);
    });
    await expect(groups(page)).toHaveCount(3);
}
const groups = page => page.locator('#overviewHosts .overview-host-group');
const order = page => groups(page).evaluateAll(nodes => nodes.map(n => n.dataset.hostDropGroup));
const card = (page, name) => page.locator(`#overviewHosts [data-host-drop-group="${name}"]`);
const arrange = async page => {
    if (await page.locator('#overviewArrangeGroups').getAttribute('aria-expanded') !== 'true') await page.locator('#overviewArrangeGroups').click();
};

for (const width of [1440, 870, 390]) {
    test(`group arrangement is compact, accessible and persistent at ${width}px`, async ({page}, testInfo) => {
        await page.setViewportSize({width,height:900});
        await login(page, 'e2e_admin', {workspace:false});
        await openClassic(page);
        await fixtures(page);
        await installSshConnectTrap(page);
        await arrange(page);
        await expect(page.locator('#overviewArrangePanel')).toBeVisible();
        await card(page,'Alpha').scrollIntoViewIfNeeded();
        await page.screenshot({path:testInfo.outputPath(`arrange-${width}.png`),animations:'disabled'});
        expect(await card(page,'Alpha').evaluate(row => {
            const bounds=row.getBoundingClientRect();
            return [...row.querySelectorAll('input,button')].every(control=>{
                const rect=control.getBoundingClientRect();
                return rect.left>=bounds.left && rect.right<=bounds.right;
            });
        })).toBe(true);
        const panel = await page.locator('#overviewArrangePanel').boundingBox();
        for (const selector of ['#overviewHostSearch', '#overviewGroupFilter']) {
            const control = await page.locator(selector).boundingBox();
            expect(control.y + control.height).toBeLessThanOrEqual(panel.y);
        }
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
        await page.locator('#overviewGraphBtn').click();
        await expect.poll(() => order(page)).toEqual(expected);
        await page.locator('#overviewListBtn').click();
        await expect.poll(() => order(page)).toEqual(expected);
        await page.locator('#overviewHostSearch').fill('Gamma');
        await expect(page.locator('#overviewHosts [data-host-id]')).toHaveCount(1);
        await expect(page.locator('#overviewHosts [data-host-id]')).toHaveAccessibleName('Open saved connection: Gamma host');
        await page.locator('#overviewHostSearch').fill('');
        await expect.poll(() => order(page)).toEqual(expected);
        await page.reload();
        await fixtures(page);
        await expect.poll(() => order(page)).toEqual(expected);
        await arrange(page);
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
    await openClassic(page);
    await fixtures(page);
    await page.evaluate(() => {
        ProfileManager.setProfiles(ProfileManager.profiles.map(p => ({...p,jump_host_id:'arrange-jump'})));
        const emit=socket.emit.bind(socket);socket.emit=()=>socket;
        SessionManager.createSession({session_id:'arrange-session',host:'lab.example',username:'admin',port:22});
        SessionManager.assignSessionToPane('arrange-session',0);SessionManager.switchSession('arrange-session');
        socket.emit=emit;
    });
    await page.locator('#overviewNavBtn').click();
    await installSshConnectTrap(page);
    const snapshot=()=>page.evaluate(()=>({profiles:ProfileManager.profiles,sessions:Object.keys(SessionManager.sessions),active:SessionManager.activeSessionId}));
    const before=await snapshot();
    expect(before.sessions).toContain('arrange-session');
    await page.locator('#overviewGraphBtn').click();
    await expect(page.locator('#overviewHosts .overview-edges path')).toHaveCount(5);
    await arrange(page);
    await card(page,'Gamma').locator('.overview-group-drag').dragTo(card(page,'Alpha').locator('.overview-group-drag'));
    await expect.poll(() => order(page)).toEqual(['Gamma','Alpha','Beta']);
    // Every saved route and every member stays attached to the same jump host.
    await expect.poll(() => page.locator('#overviewHosts .overview-edges path').evaluateAll(paths => paths.map(p => [p.dataset.sourceId,p.dataset.targetId]).sort())).toEqual(
        ['alpha','beta-0','beta-1','beta-2','gamma'].map(id => ['arrange-jump',id]),
    );
    for(const [group,names] of Object.entries({Gamma:['Gamma host'],Alpha:['Alpha host'],Beta:['Beta host 0','Beta host 1','Beta host 2']})) {
        await page.locator('#overviewGroupFilter').selectOption('group:'+group);
        await expect(page.locator('#overviewHosts .overview-graph-branch[data-jump-id="arrange-jump"]')).toHaveCount(1);
        await expect(page.locator('#overviewHosts [data-host-id]')).toHaveCount(names.length);
        for(const name of names) await expect(page.getByRole('button',{name:`Open saved connection: ${name}`,exact:true})).toBeVisible();
        await page.locator('#overviewGroupFilter').selectOption('');
    }
    expect(await snapshot()).toEqual(before);
    expect(await page.evaluate(() => window.__sshConnectAttempts)).toEqual([]);
    // A changed account scope does not inherit this account's saved order.
    await page.route('**/', async route => {
        const response=await route.fetch();
        const body=(await response.text()).replace(/name="background-scope" content="[a-f0-9]{64}"/,`name="background-scope" content="${'b'.repeat(64)}"`);
        await route.fulfill({response,body});
    });
    await page.reload();await fixtures(page);
    await expect.poll(() => order(page)).toEqual(['Alpha','Beta','Gamma']);
    await assertNoExternalRequests(page);
});

test('unavailable browser storage keeps arrangement usable and reports it honestly', async ({page}) => {
    await login(page,'e2e_admin',{workspace:false});await openClassic(page);await fixtures(page);
    await page.evaluate(() => {
        const original=Storage.prototype.setItem;
        Storage.prototype.setItem=function(key,value){if(key.startsWith('webssh:overview-group-order:'))throw new DOMException('Blocked','QuotaExceededError');return original.call(this,key,value);};
    });
    await arrange(page);await page.locator('#overviewSortGroupsDesc').click();
    await expect.poll(() => order(page)).toEqual(['Gamma','Beta','Alpha']);
    await expect(page.locator('#overviewArrangeStatus')).toContainText('could not be saved');
    for(const invalid of ['999','0','1.5','']) {
        await card(page,'Alpha').locator('input').fill(invalid);await card(page,'Alpha').locator('input').press('Enter');
        await expect.poll(() => order(page)).toEqual(['Gamma','Beta','Alpha']);
        await expect(card(page,'Alpha').locator('input')).toHaveValue('3');
    }
    await page.reload();await fixtures(page);
    await expect.poll(() => order(page)).toEqual(['Alpha','Beta','Gamma']);
    await assertNoExternalRequests(page);
});

test('arrangement controls support every language/theme, large stores and empty results', async ({page}) => {
    test.setTimeout(180000);
    await page.setViewportSize({width:390,height:844});
    const errors=[];page.on('pageerror',error=>errors.push(error.message));
    await login(page,'e2e_admin',{workspace:false});await openClassic(page);await fixtures(page);await arrange(page);
    for(const [language,label] of Object.entries({en:'Arrange groups',de:'Gruppen anordnen',vi:'Sắp xếp nhóm',fr:'Organiser les groupes',es:'Organizar grupos',zh:'排列分组'})) {
        await page.evaluate(lang=>i18n.setLanguage(lang),language);
        await expect(page.locator('#overviewArrangeGroups')).toHaveAccessibleName(label);
        expect(await page.locator('#overviewArrangePanel').evaluate(el=>el.scrollWidth<=el.clientWidth)).toBe(true);
    }
    await page.evaluate(()=>i18n.setLanguage('en'));
    for(const theme of ['glass','solar','paper','noir','arctic-ice','rose-gold','obsidian','retro','cyberpunk-neon','emerald-matrix']) {
        await page.evaluate(theme=>document.body.dataset.theme=theme,theme);
        const colors=await card(page,'Alpha').locator('input').evaluate(el=>({color:getComputedStyle(el).color,background:getComputedStyle(el).backgroundColor}));
        expect(colors.color).not.toBe(colors.background);
        expect(await page.locator('#connectionOverview').evaluate(el=>el.scrollWidth<=el.clientWidth)).toBe(true);
    }
    await page.locator('#overviewHostSearch').fill('no such host');
    await expect(page.locator('#overviewHosts .overview-empty')).toBeVisible();
    await expect(groups(page)).toHaveCount(0);
    await page.locator('#overviewHostSearch').fill('');
    const names=Array.from({length:500},(_,i)=>`Group ${String(i).padStart(3,'0')}`);
    await page.evaluate(names=>ProfileManager.setProfiles(names.map((group,i)=>({id:`group-${i}`,name:`Host ${i}`,group}))),names);
    await expect(groups(page)).toHaveCount(500);
    await page.locator('#overviewSortGroupsDesc').click();
    await expect.poll(() => order(page)).toEqual([...names].reverse());
    // Firefox's DOMRect subtraction can differ by 1/65536 CSS pixel at a shared edge.
    await expect.poll(() => groups(page).evaluateAll(rows => Math.min(...rows.slice(1).map((row,i) => Math.round((row.getBoundingClientRect().top - rows[i].getBoundingClientRect().bottom)*1000)/1000)))).toBeGreaterThanOrEqual(0);
    await expect(page.locator('.overview-host-move option')).toHaveCount(0);
    await card(page,'Group 000').locator('input').fill('1');await card(page,'Group 000').locator('input').press('Enter');
    await page.locator('#overviewGroupFilter').selectOption('group:Group 000');
    await expect(groups(page)).toHaveCount(1);
    await expect(card(page,'Group 000').locator('input')).toHaveValue('1');
    await page.locator('#overviewGroupFilter').selectOption('');
    await page.locator('#overviewSortGroupsAsc').click();
    await page.locator('#overviewHostSearch').fill('Host 499');
    await expect(page.getByRole('button',{name:'Open saved connection: Host 499',exact:true})).toBeVisible();
    expect(errors).toEqual([]);await assertNoExternalRequests(page);
});
