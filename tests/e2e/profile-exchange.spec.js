const {test, expect} = require('playwright/test');
const {login, openProfileManagement, assertNoExternalRequests} = require('./helpers');

test.afterEach(async ({page}) => assertNoExternalRequests(page));

test('known_hosts gets format guidance and repeated warnings stay collapsed', async ({page}) => {
    await login(page);
    await openProfileManagement(page);
    await page.locator('#importProfilesBtn').click();
    const dialog = page.getByRole('dialog', {name: 'Import hosts', exact: true});
    await dialog.locator('input[type="file"]').setInputFiles({
        name: 'known_hosts', mimeType: 'text/plain',
        buffer: Buffer.from('server.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA\n'.repeat(12))
    });
    await expect(dialog.getByLabel('Configuration text')).toHaveValue(/ssh-ed25519/);
    await dialog.getByRole('button', {name: 'Preview', exact: true}).click();
    await expect(dialog.getByRole('status')).toContainText('known_hosts');
    await expect(dialog.getByRole('status')).toContainText('~/.ssh/config');
    await expect(dialog.locator('fieldset')).toHaveCount(0);
    await expect(dialog.getByRole('button', {name: 'Import selected hosts'})).toBeDisabled();
    await dialog.getByLabel('Configuration text').fill('ForwardAgent yes\n'.repeat(12));
    await expect(dialog.getByRole('status')).toBeEmpty();
    await dialog.getByRole('button', {name: 'Preview', exact: true}).click();
    await expect(dialog.getByRole('status')).toContainText('No supported hosts');
    await expect(dialog.locator('summary')).toHaveText('Warnings (12)');
    await expect(dialog.locator('.exchange-warnings ul')).toBeHidden();
    await dialog.locator('summary').click();
    await expect(dialog.locator('.exchange-warnings li')).toHaveCount(12);
});

test('host import previews, requires explicit submission and skips retries', async ({page}) => {
    await login(page);
    await openProfileManagement(page);
    await page.locator('#importProfilesBtn').click();
    const dialog = page.getByRole('dialog', {name: 'Import hosts', exact: true});
    await dialog.getByLabel('Configuration text').fill('Host exchange-browser-test\n HostName example.test\n User deploy');
    await expect(dialog.getByRole('button', {name: 'Import selected hosts'})).toBeDisabled();
    await dialog.getByRole('button', {name: 'Preview', exact: true}).click();
    await expect(dialog.locator('fieldset')).toContainText('deploy@example.test:22');
    await dialog.getByRole('button', {name: 'Import selected hosts'}).click();
    await expect(dialog.getByRole('status')).toContainText('Imported');
    await dialog.getByRole('button', {name: 'Preview', exact: true}).click();
    await dialog.getByRole('button', {name: 'Import selected hosts'}).click();
    await expect(dialog.getByRole('status')).toContainText('Skipped');
    await dialog.getByRole('button', {name: 'Close', exact: true}).click();
    await expect(dialog).toHaveCount(0);
});

test('unsafe routing is blocked and source edits invalidate preview', async ({page}) => {
    await login(page);
    await openProfileManagement(page);
    await page.locator('#importProfilesBtn').click();
    const dialog = page.getByRole('dialog', {name: 'Import hosts', exact: true});
    const source = dialog.getByLabel('Configuration text');
    await source.fill('Host unsafe\n User deploy\n ProxyCommand touch /tmp/never');
    await dialog.getByRole('button', {name: 'Preview', exact: true}).click();
    await expect(dialog.getByRole('checkbox')).toBeDisabled();
    await expect(dialog.getByRole('button', {name: 'Import selected hosts'})).toBeDisabled();
    await source.fill('Host safe\n User deploy');
    await dialog.getByRole('button', {name: 'Preview', exact: true}).click();
    await expect(dialog.getByRole('button', {name: 'Import selected hosts'})).toBeEnabled();
    await source.fill('Host changed\n User deploy');
    await expect(dialog.getByRole('button', {name: 'Import selected hosts'})).toBeDisabled();
    await expect(dialog.locator('fieldset')).toHaveCount(0);
});
