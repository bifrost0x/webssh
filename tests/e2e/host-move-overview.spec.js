const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');
for (const graph of [false, true]) {
    test(`Overview ${graph ? 'routes' : 'list'} moves hosts through the existing organization contract`, async ({page}) => {
        await login(page, 'e2e_admin', {workspace:false});
        await page.evaluate(() => {
            const template = window.ProfileManager.profiles[0];
            window.ProfileManager.setProfiles([
                {...template, id:'move-a', name:'Move A', group:'Source', favorite:false},
                {...template, id:'move-b', name:'Move B', group:'Target', favorite:false},
            ]);
            const original = window.socket.emit.bind(window.socket);
            window.__moves = []; window.__ssh = [];
            window.socket.emit = (event, payload, ack) => {
                if (event === 'ssh_connect') { window.__ssh.push(payload); return; }
                if (event !== 'move_profile') return original(event, payload, ack);
                window.__moves.push(payload);
                ack({success:true, organization:[{id:payload.profile_id, group:payload.target_group, sort_order:payload.target_index}]});
            };
        });
        if (graph) await page.locator('#overviewGraphBtn').click();
        const host = page.locator('#overviewHosts [data-host-id="move-a"]');
        await host.dragTo(page.locator('#overviewHosts [data-host-drop-group="Target"]').first());
        await expect.poll(() => page.evaluate(() => window.__moves.length)).toBe(1);
        expect(await page.evaluate(() => window.__moves[0])).toEqual({profile_id:'move-a',expected_source_group:'Source',target_group:'Target',target_index:1,confirm_source_group_removal:false});
        await expect(page.locator('#overviewHosts [data-host-drop-group="Target"] [data-host-id="move-a"]')).toBeVisible();
        const row = page.locator('#overviewHosts .overview-host-entry').filter({has: page.locator('[data-host-id="move-a"]')});
        await row.locator('summary').click();
        await row.locator('select').selectOption('');
        await expect.poll(() => page.evaluate(() => window.__moves.length)).toBe(2);
        await expect(page.locator('#overviewHosts [data-host-drop-group=""] [data-host-id="move-a"]')).toBeVisible();
        expect(await page.evaluate(() => window.__ssh)).toEqual([]);
        await assertNoExternalRequests(page);
    });
}
