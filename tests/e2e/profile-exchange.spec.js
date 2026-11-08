const {test, expect} = require('playwright/test');
const {login, openProfileManagement, assertNoExternalRequests} = require('./helpers');

test.afterEach(async ({page}) => assertNoExternalRequests(page));

test('known_hosts gets format guidance and repeated warnings stay collapsed', async ({page}) => {
    await login(page);
    await openProfileManagement(page);
    await page.locator('#importProfilesBtn').locator('xpath=ancestor::details').locator('summary').click();
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

test('host import previews, requires explicit submission and skips retries', async ({page}, testInfo) => {
    await login(page);
    await openProfileManagement(page);
    await page.locator('#importProfilesBtn').locator('xpath=ancestor::details').locator('summary').click();
    await page.locator('#importProfilesBtn').click();
    const dialog = page.getByRole('dialog', {name: 'Import hosts', exact: true});
    const host = `exchange-${testInfo.project.name || 'default'}.example.test`;
    await dialog.getByLabel('Configuration text').fill(`Host exchange-browser-test\n HostName ${host}\n User deploy`);
    await expect(dialog.getByRole('button', {name: 'Import selected hosts'})).toBeDisabled();
    await dialog.getByRole('button', {name: 'Preview', exact: true}).click();
    await expect(dialog.locator('fieldset')).toContainText(`deploy@${host}:22`);
    await dialog.getByRole('button', {name: 'Import selected hosts'}).click();
    await expect(dialog.getByRole('status')).toContainText('Imported');
    await dialog.getByRole('button', {name: 'Preview', exact: true}).click();
    await dialog.getByRole('button', {name: 'Import selected hosts'}).click();
    await expect(dialog.getByRole('status')).toContainText('Skipped');
    await dialog.getByRole('button', {name: 'Close', exact: true}).click();
    await expect(dialog).toHaveCount(0);
    await expect.poll(() => page.evaluate(host => window.ProfileManager.profiles.some(profile => profile.host === host), host)).toBe(true);
    await page.evaluate(host => {
        const profile = window.ProfileManager.profiles.find(item => item.host === host);
        return new Promise(resolve => window.socket.emit('delete_profile', {profile_id: profile.id}, resolve));
    }, host);
});

test('unsafe routing is blocked and source edits invalidate preview', async ({page}) => {
    await login(page);
    await openProfileManagement(page);
    await page.locator('#importProfilesBtn').locator('xpath=ancestor::details').locator('summary').click();
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

test('import availability follows the selected hosts and stays locked after submission', async ({page}) => {
    await login(page);
    await openProfileManagement(page);
    await page.locator('#importProfilesBtn').locator('xpath=ancestor::details').locator('summary').click();
    await page.locator('#importProfilesBtn').click();
    const dialog=page.getByRole('dialog',{name:'Import hosts',exact:true});
    await dialog.getByLabel('Configuration text').fill('Host selection-test\n HostName selection.example\n User deploy');
    await dialog.getByRole('button',{name:'Preview',exact:true}).click();
    const selected=dialog.getByRole('checkbox');
    const submit=dialog.getByRole('button',{name:'Import selected hosts'});
    await expect(selected).toBeChecked();
    await selected.uncheck();
    await expect(submit).toBeDisabled();
    await selected.check();
    await expect(submit).toBeEnabled();
    let finish;
    await page.route('**/api/profiles/exchange',async route=>{
        await new Promise(resolve=>{finish=()=>route.fulfill({json:{results:[{index:0,status:'imported'}]}}).then(resolve);});
    });
    await submit.click();
    await expect.poll(()=>Boolean(finish)).toBe(true);
    await selected.uncheck(); await selected.check();
    await expect(submit).toBeDisabled();
    await finish();
    await expect(dialog.getByRole('status')).toContainText('Imported');
    await selected.uncheck(); await selected.check();
    await expect(submit).toBeDisabled();
});
