const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests, installSshConnectTrap} = require('./helpers');

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
const groups = page => page.locator('#overviewHosts .overview-list-group');
const order = page => groups(page).evaluateAll(nodes => nodes.map(n => n.querySelector('h3').firstChild.textContent));
const card = (page, name) => groups(page).filter({has:page.locator('h3', {hasText:new RegExp(`^${name}\\d+$`)})});
const arrange = async page => {
    if (await page.locator('#overviewArrangeGroups').getAttribute('aria-expanded') !== 'true') await page.locator('#overviewArrangeGroups').click();
};

for (const width of [1440, 870, 390]) {
    test(`group arrangement is compact, accessible and persistent at ${width}px`, async ({page}, testInfo) => {
        await page.setViewportSize({width,height:900});
        await login(page, 'e2e_admin', {workspace:false});
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
        for (const selector of ['#overviewHostSearch', '#overviewGroupFilter', '#overviewCreateHost']) {
            const control = await page.locator(selector).boundingBox();
            expect(control.y + control.height).toBeLessThanOrEqual(panel.y);
        }
        // Firefox's DOMRect subtraction can differ by 1/65536 CSS pixel at a shared edge.
        // Round to a thousandth of a pixel; every rendered overlap still fails.
        await expect.poll(() => groups(page).evaluateAll(rows => Math.min(...rows.slice(1).map((row,i) => Math.round((row.getBoundingClientRect().top - rows[i].getBoundingClientRect().bottom)*1000)/1000)))).toBeGreaterThanOrEqual(0);
        await card(page,'Gamma').locator('input').fill('1');
        await card(page,'Gamma').locator('input').press('Enter');
        await expect.poll(() => order(page)).toEqual(['Gamma','Alpha','Beta']);
        await expect(card(page,'Gamma').locator('input')).toBeFocused();
        await expect(page.locator('#overviewArrangeStatus')).toContainText('saved');
        if (width === 1440) {
            await card(page,'Beta').locator('.overview-group-drag').dragTo(card(page,'Gamma').locator('.overview-group-drag'));
            await expect.poll(() => order(page)).toEqual(['Beta','Gamma','Alpha']);
        }
        const expected = await order(page);
        await page.locator('#overviewHosts [data-host-id]').first().click();
        await expect(page.locator('.overview-selected-path')).toBeVisible();
        if (await page.locator('.overview-access-inspector').count()) await page.locator('.overview-access-heading button').click();
        await expect.poll(() => order(page)).toEqual(expected);
        await page.locator('#overviewHostSearch').fill('Gamma');
        await expect(page.locator('#overviewHosts .overview-host-connect')).toHaveCount(1);
        await expect(page.locator('#overviewHosts .overview-host-connect')).toHaveAccessibleName('Connect Gamma host');
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
    await arrange(page);
    const source = card(page,'Gamma').locator('.overview-group-drag');
    await source.scrollIntoViewIfNeeded();
    const sourceBox = await source.boundingBox();
    await page.mouse.move(sourceBox.x + sourceBox.width / 2, sourceBox.y + sourceBox.height / 2);
    await page.mouse.down();
    await page.mouse.move(sourceBox.x + sourceBox.width / 2 + 12, sourceBox.y + sourceBox.height / 2, {steps:4});
    const listBox = await page.locator('.overview-compact-list').boundingBox();
    await page.mouse.move(listBox.x + 18, listBox.y + 4, {steps:8});
    await expect.poll(()=>page.locator('.overview-compact-list').evaluate(el=>el.scrollTop)).toBe(0);
    const targetBox = await card(page,'Alpha').locator('.overview-group-drag').boundingBox();
    await page.mouse.move(targetBox.x + targetBox.width / 2, targetBox.y + targetBox.height / 2, {steps:4});
    await page.mouse.up();
    await expect.poll(() => order(page)).toEqual(['Gamma','Alpha','Beta']);
    // Inspect every route and every member in the user-visible path view, rather than decorative SVG edges.
    for(const [group,names] of Object.entries({Gamma:['Gamma host'],Alpha:['Alpha host'],Beta:['Beta host 0','Beta host 1','Beta host 2']})) {
        await page.locator('#overviewGroupFilter').selectOption('group:'+group);
        await page.locator('#overviewHosts [data-host-id]').first().click();
        await expect(page.locator('.overview-path-stops > li > strong')).toHaveText(['WebSSH server','Bastion',names[0]]);
        await expect(page.locator('#overviewHosts .overview-host-connect')).toHaveCount(names.length);
        for(const name of names) await expect(page.getByRole('button',{name:`Connect ${name}`,exact:true})).toBeVisible();
        if (await page.locator('.overview-access-inspector').count()) await page.locator('.overview-access-heading button').click();
        await page.locator('#overviewGroupFilter').selectOption('');
    }
    expect(await snapshot()).toEqual(before);
    expect(await page.evaluate(() => window.__sshConnectAttempts)).toEqual([]);
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
    await login(page,'e2e_admin',{workspace:false});await fixtures(page);
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
    await login(page,'e2e_admin',{workspace:false});await fixtures(page);await arrange(page);
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
    await card(page,'Group 000').locator('input').fill('1');await card(page,'Group 000').locator('input').press('Enter');
    await page.locator('#overviewGroupFilter').selectOption('group:Group 000');
    await expect(groups(page)).toHaveCount(1);
    await expect(card(page,'Group 000').locator('input')).toHaveValue('1');
    await page.locator('#overviewGroupFilter').selectOption('');
    await page.locator('#overviewSortGroupsAsc').click();
    await page.locator('#overviewHostSearch').fill('Host 499');
    await expect(page.getByRole('button',{name:'Connect Host 499',exact:true})).toBeVisible();
    expect(errors).toEqual([]);await assertNoExternalRequests(page);
});
