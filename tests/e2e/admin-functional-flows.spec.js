const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');

async function reauthenticate(page) {
    await expect(page.locator('#stepUpModal')).toBeVisible();
    await page.locator('#stepUpPassword').fill('browser-password');
    await page.locator('#stepUpSubmit').click();
    await expect(page.locator('#stepUpModal')).not.toBeVisible();
}

for (const width of [1536, 390]) {
    test(`user creation, role changes, locking and deletion work at ${width}px`, async ({page}) => {
        await page.setViewportSize({width, height: 960});
        await login(page);
        await page.goto('/admin');
        const username = `functional_user_${width}`;
        await page.locator('#adminAddUserBtn').click();
        await page.locator('#newUsername').fill(username);
        await page.locator('#newPassword').fill('Isolated-browser-test-42!');
        await page.locator('#submitNewUser').click();
        await reauthenticate(page);
        const row = page.locator(`#adminUsersBody tr[data-username="${username}"]`);
        await expect(row).toHaveAttribute('data-role', 'user');
        await page.locator('#adminUserSearch').fill(username);
        for (const [action, attribute, value] of [
            ['promote', 'data-role', 'admin'],
            ['demote', 'data-role', 'user'],
            ['lock', 'data-locked', 'true'],
            ['unlock', 'data-locked', 'false'],
        ]) {
            await row.locator('summary').click();
            await row.locator(`[data-act="${action}"]`).click();
            await reauthenticate(page);
            await expect(row).toHaveAttribute(attribute, value);
        }
        await page.reload();
        await expect(row).toHaveAttribute('data-role', 'user');
        await expect(row).toHaveAttribute('data-locked', 'false');
        await row.locator('summary').click();
        page.once('dialog', dialog => dialog.dismiss());
        await row.locator('[data-act="delete"]').click();
        await expect(row).toHaveCount(1);
        await expect(page.locator('#stepUpModal')).not.toBeVisible();
        page.once('dialog', dialog => dialog.accept());
        await row.locator('summary').click();
        await row.locator('[data-act="delete"]').click();
        await reauthenticate(page);
        await expect(row).toHaveCount(0);
        await page.reload();
        await expect(row).toHaveCount(0);
        await assertNoExternalRequests(page);
    });
}

for (const width of [1536, 390, 3440]) {
    test(`backup creation, verification and restore cancellation work at ${width}px`, async ({page}, testInfo) => {
        test.setTimeout(60_000);
        page.setDefaultTimeout(10_000);
        await page.setViewportSize({width, height: 960});
        await login(page);
        await page.goto('/settings#backup');
        await expect(page.locator('#tab-backup [data-i18n="backup.sensitiveWarning"]')).toContainText('exclude saved remote passwords and SSH keys');
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
        await page.locator('#backupCreateBtn').click();
        if (width === 1536) {
            // Exercise keyboard submission in this real backup round trip rather
            // than creating a fourth backup against the three-per-hour limit.
            const input = page.locator('#stepUpPassword');
            await expect(input).toBeFocused();
            await input.press('Enter');
            await expect(page.locator('#stepUpModal')).toBeVisible();
            let creations = 0;
            page.on('request', request => {
                if (request.method() === 'POST' && new URL(request.url()).pathname === '/admin/api/backups') creations++;
            });
            await input.fill('browser-password');
            await input.press('Enter');
            await expect(page.locator('#stepUpModal')).not.toBeVisible();
            await expect(page.locator('#backupDownloadBtn')).toBeEnabled({timeout: 20_000});
            expect(creations).toBe(1);
        } else {
            await reauthenticate(page);
        }
        await expect(page.locator('#backupDownloadBtn')).toBeEnabled({timeout: 20_000});
        const downloading = page.waitForEvent('download');
        await page.locator('#backupDownloadBtn').click();
        await reauthenticate(page);
        const download = await downloading;
        expect(download.suggestedFilename()).toBe('webssh-backup.zip');
        await expect(page.locator('#backupDownloadBtn')).toBeDisabled();
        await page.locator('#backupUploadFile').setInputFiles(await download.path());
        await page.locator('#backupUploadBtn').click();
        await reauthenticate(page);
        await expect(page.locator('#backupCompatible')).toHaveText('Yes', {timeout: 20_000});
        await expect(page.locator('#backupRestoreBtn')).toBeEnabled();
        await page.locator('#backupRestoreBtn').click();
        await expect(page.locator('#restoreFirstConfirmModal')).toBeVisible();
        await expect(page.locator('#restoreFirstConfirmModal')).toContainText('SSH keys');
        await expect(page.locator('#restoreFirstConfirmModal')).toHaveCSS('opacity', '1');
        await page.screenshot({path: testInfo.outputPath(`restore-policy-${width}.png`)});
        await page.locator('#restoreFirstAcknowledge').check();
        await page.locator('#restoreFirstContinue').click();
        await reauthenticate(page);
        await expect(page.locator('#restoreSecondConfirmModal')).toBeVisible();
        await page.locator('#restoreSecondCancel').click();
        await expect(page.locator('#restoreSecondConfirmModal')).not.toBeVisible();
        await page.goto('/admin');
        await expect(page.locator('#adminUsersBody')).toContainText('e2e_admin');
        await assertNoExternalRequests(page);
    });
}
