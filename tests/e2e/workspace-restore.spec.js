const { test, expect } = require('playwright/test');
const { openWorkspace, login } = require('./helpers');

test.use({ viewport: { width: 1920, height: 1080 } });

for (const transport of ['polling', 'websocket']) {
    for (const { count, width } of [
        { count: 1, width: 1666 }, { count: 12, width: 1666 },
        { count: 1, width: 390 }, { count: 12, width: 390 },
    ]) {
        test(`workspace tools survive resize and reload with ${count} sessions over ${transport} at ${width}px`, async ({ page }) => {
            await page.route('**/static/js/app.js?*', async route => {
                const response = await route.fetch();
                const body = (await response.text()).replace('autoConnect: false,',
                    `autoConnect: false, transports: ['${transport}'], upgrade: false,`);
                await route.fulfill({ response, body });
            });
            // A pending POST makes the startup burst accumulate as on a slower link.
            if (transport === 'polling') {
                await page.route('**/socket.io/**', async route => {
                    if (route.request().method() === 'POST') {
                        await new Promise(resolve => setTimeout(resolve, 100));
                    }
                    await route.continue();
                });
            }
            const packets = [];
            const errors = [];
            page.on('pageerror', error => errors.push(error.message));
            page.on('request', request => {
                if (request.method() === 'POST' && request.url().includes('/socket.io/')) {
                    packets.push((request.postData() || '').split('\x1e'));
                }
            });
            await login(page);
            const seeded = await page.evaluate(count => new Promise(resolve => (
                window.socket.emit('e2e_workspace_restore', { count }, resolve)
            )), count);
            expect(seeded.ok).toBe(true);
            try {
                await page.setViewportSize({ width, height: 920 });
                packets.length = 0;
                await page.reload();
                await openWorkspace(page);
                await expect(page.locator('.session-tab')).toHaveCount(count);
                if (width < 768) await page.locator('#contextWorkspaceLauncher').click();
                await page.locator('#contextCommandsTab').click();
                await expect(page.locator('.session-command-results')).toContainText('E2E command', { timeout: 4000 });
                await page.locator('#contextFilesTab').click();
                await expect(page.locator('#sessionFilesMount')).toContainText('reload-proof.txt', { timeout: 4000 });
                await page.locator('#contextDiagnosticsTab').click();
                await expect(page.locator('#sessionDiagnosticsOs')).toContainText('Reload fixture Linux', { timeout: 4000 });
                expect(errors).toEqual([]);
                expect(Math.max(0, ...packets.map(items => items.length))).toBeLessThanOrEqual(16);
            } finally {
                if (test.info().status !== test.info().expectedStatus) {
                    console.log('RESTORE PACKETS', JSON.stringify(packets));
                }
                await page.evaluate(() => new Promise(resolve => window.socket.emit('e2e_workspace_restore', { count: 0 }, resolve)));
                await page.unroute('**/socket.io/**');
                const closed = transport === 'polling'
                    ? page.waitForResponse(response => response.request().method() === 'POST'
                        && (response.request().postData() || '').split('\x1e').includes('1'))
                    : Promise.resolve();
                await page.evaluate(() => window.socket.disconnect());
                await closed;
            }
        });
    }
}
