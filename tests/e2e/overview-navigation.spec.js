const {test, expect} = require('playwright/test');
const {login, assertNoExternalRequests} = require('./helpers');

test('recent connections leave the form untouched while another connection is pending', async ({page}) => {
    await login(page);
    await expect.poll(() => page.evaluate(() => ProfileManager.keysLoaded)).toBe(true);
    await page.evaluate(() => {
        ConnectionHistory.addConnection('history.example.invalid', 2222, 'history-user');
        window.openDefaultConnectionModal();
        document.getElementById('cancelConnectionBtn').click();
        // Keep a real saved-profile attempt pending without contacting SSH.
        const emit = window.socket.emit.bind(window.socket);
        window.__pendingConnects = [];
        window.socket.emit = (event, ...args) => {
            if (event === 'ssh_connect') {
                window.__pendingConnects.push(args[0]);
                return window.socket;
            }
            return emit(event, ...args);
        };
        document.getElementById('hostInput').value = 'unchanged.example.invalid';
        document.getElementById('usernameInput').value = 'unchanged-user';
        document.getElementById('portInput').value = '2200';
        window.launchProfileForPane(ProfileManager.profiles.find(item => item.name === 'Usable key').id);
    });
    await expect.poll(() => page.evaluate(() => window.__pendingConnects.length)).toBe(1);
    await page.locator('#overviewNavBtn').click();
    await page.locator('#overviewHistory button').click();
    await expect(page.locator('#connectionModal')).not.toHaveClass(/show/);
    await expect(page.locator('#hostInput')).toHaveValue('unchanged.example.invalid');
    await expect(page.locator('#portInput')).toHaveValue('2200');
    await expect(page.locator('#usernameInput')).toHaveValue('unchanged-user');
    expect(await page.evaluate(() => window.__pendingConnects.length)).toBe(1);
    await assertNoExternalRequests(page);
});
