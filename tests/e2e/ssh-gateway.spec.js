const {test, expect} = require('playwright/test');
const {login: loginDefault, assertNoExternalRequests} = require('./helpers');

async function login(page) {
    await loginDefault(page);
    // Dialog tests simulate an enabled workspace and synthetic gateway events.
    await page.evaluate(() => {
        document.querySelector('meta[name="ssh-gateway-enabled"]').content = 'true';
    });
}

test('gateway integration is disabled by default in the workspace', async ({page}) => {
    await loginDefault(page);
    await page.evaluate(() => window.openDefaultConnectionModal());
    const requiredBefore = await page.locator('#passwordInput').evaluate(input => input.required);
    await page.locator('#usernameInput').fill('user:target');
    await expect(page.locator('#passwordHint')).toHaveText('');
    await expect(page.locator('#passwordInput')).toHaveJSProperty('required', requiredBefore);
    expect(await page.evaluate(() => window.ConnectionValidation.isValidUsername('user:target', true))).toBe(false);
    expect(await page.evaluate(() => {
        window.SSHGatewayDialog.prepare({username: 'user:target', client_request_id: 'disabled'});
        return window.SSHGatewayDialog.has('disabled');
    })).toBe(false);
});

test('admin enables and disables the gateway using the protected settings control', async ({page}) => {
    await loginDefault(page);
    await page.goto('/settings#integrations');
    const toggle = page.locator('#settingSshGateway');
    await expect(toggle).toBeEnabled();
    await expect(toggle).not.toBeChecked();
    try {
        await toggle.check();
        await expect(page.locator('#stepUpModal')).toHaveClass(/show/);
        await page.locator('#stepUpPassword').fill('browser-password');
        await page.locator('#stepUpSubmit').click();
        await expect(toggle).toBeEnabled();
        await expect(toggle).toBeChecked();
        await page.goto('/');
        await expect(page.locator('meta[name="ssh-gateway-enabled"]')).toHaveAttribute('content', 'true');
    } finally {
        await page.goto('/settings#integrations');
        await expect(toggle).toBeEnabled();
        if (await toggle.isChecked()) {
            await toggle.uncheck();
            await expect(page.locator('#stepUpModal')).toHaveClass(/show/);
            await page.locator('#stepUpPassword').fill('browser-password');
            await page.locator('#stepUpSubmit').click();
            await expect(toggle).toBeEnabled();
            await expect(toggle).not.toBeChecked();
        }
    }
    await page.goto('/');
    await expect(page.locator('meta[name="ssh-gateway-enabled"]')).toHaveAttribute('content', 'false');
});

test('gateway challenges are correlated, masked, text-only and transient', async ({page}) => {
    await login(page);
    await page.evaluate(() => {
        window.openDefaultConnectionModal();
        window.__gatewaySent = [];
        const original = window.socket.emit.bind(window.socket);
        window.socket.emit = (event, data, ack) => {
            if (event.startsWith('ssh_gateway_')) {
                window.__gatewaySent.push({event, data: structuredClone(data)});
                ack?.({success: true});
                return;
            }
            return original(event, data, ack);
        };
        const dispatch = data => window.socket.listeners('ssh_gateway_challenge').forEach(fn => fn(data));
        dispatch({client_request_id: 'unsolicited', prompts: []});
        window.SSHGatewayDialog.prepare({username: 'user:target', client_request_id: 'gateway-test'}, true);
        dispatch({
            client_request_id: 'gateway-test', challenge_id: 'one-shot',
            title: '<img src=x onerror=alert(1)>',
            instructions: 'Approve https://example.test/approval then return. javascript:alert(1)',
            prompts: [{label: '<script>bad()</script>'}],
        });
    });
    const modal = page.locator('#sshGatewayModal');
    await expect(modal).toHaveClass(/show/);
    await expect(modal.locator('img,script')).toHaveCount(0);
    await expect(modal.locator('input')).toHaveAttribute('type', 'password');
    await expect(modal.locator('a')).toHaveCount(1);
    await expect(modal.locator('a')).toHaveAttribute('rel', 'noopener noreferrer');
    await modal.locator('input').fill('123456');
    await modal.locator('button[type=submit]').click();
    await expect(modal.locator('input')).toHaveValue('');
    expect(await page.evaluate(() => window.__gatewaySent[0])).toEqual({
        event: 'ssh_gateway_answer',
        data: {client_request_id: 'gateway-test', challenge_id: 'one-shot', answers: ['123456']},
    });
    await modal.locator('button[type=button]').click();
    expect(await page.evaluate(() => window.__gatewaySent[1])).toEqual({
        event: 'ssh_gateway_quick_cancel',
        data: {client_request_id: 'gateway-test'},
    });
    await expect(page.locator('#connectionModal')).toHaveClass(/show/);
    await expect(modal).not.toHaveClass(/show/);
    await expect(modal.locator('input')).toHaveCount(0);
    assertNoExternalRequests(page);
});

test('ordinary passwords stay required and gateway passwords can be empty', async ({page}) => {
    await login(page);
    await page.evaluate(() => window.openDefaultConnectionModal());
    await page.locator('#hostInput').fill('example.com');
    await page.locator('#usernameInput').fill('ordinary');
    await expect(page.locator('#passwordHint')).toHaveText('');
    await page.locator('#authTypeSelect').selectOption('key');
    await page.locator('#authTypeSelect').selectOption('password');
    await expect(page.locator('#passwordInput')).toHaveJSProperty('required', true);
    await page.evaluate(() => {
        window.__ordinaryConnects = [];
        const original = window.socket.emit.bind(window.socket);
        window.socket.emit = (event, data, ...args) => {
            if (event === 'ssh_connect') {
                window.__ordinaryConnects.push(data);
                return;
            }
            return original(event, data, ...args);
        };
    });
    await page.locator('#connectBtn').click();
    await expect(page.locator('#passwordInput')).toBeFocused();
    expect(await page.evaluate(() => window.__ordinaryConnects.length)).toBe(0);
    await page.locator('#usernameInput').fill('user:target');
    await expect(page.locator('#passwordInput')).toHaveJSProperty('required', false);
    const gatewayHint = await page.evaluate(() => window.i18n.t('gateway.passwordHint'));
    const requiredHint = await page.evaluate(() => window.i18n.t('connection.passwordRequired'));
    await expect(page.locator('#passwordHint')).toHaveText(gatewayHint);
    await page.locator('#usernameInput').fill('ordinary');
    await expect(page.locator('#passwordHint')).toHaveText(requiredHint);
    await page.locator('#passwordInput').fill('test-password');
    await expect(page.locator('#passwordHint')).toHaveText('');
    await page.locator('#usernameInput').fill('user:target');
    await page.locator('#passwordInput').fill('');
    await expect(page.locator('#passwordHint')).toHaveText(gatewayHint);
    await page.locator('#authTypeSelect').selectOption('key');
    await page.locator('#authTypeSelect').selectOption('password');
    await expect(page.locator('#passwordInput')).toHaveJSProperty('required', false);
    await expect(page.locator('#passwordHint')).toHaveText(gatewayHint);
    await page.locator('#usernameInput').fill('ordinary');
    await page.locator('#passwordInput').fill('test-password');
    await page.locator('#connectBtn').click();
    expect(await page.evaluate(() => window.__ordinaryConnects.map(data => data.username))).toEqual(['ordinary']);
    assertNoExternalRequests(page);
});

test('concurrent gateway prompts restore the pending terminal and its input routing', async ({page}) => {
    await login(page);
    await page.evaluate(() => {
        window.__gatewayInputs = [];
        const original = window.socket.emit.bind(window.socket);
        window.socket.emit = (event, data, ack) => {
            if (event === 'ssh_gateway_input') {
                window.__gatewayInputs.push(data);
                return;
            }
            return original(event, data, ack);
        };
        const dispatch = (event, data) => window.socket.listeners(event).forEach(fn => fn(data));
        for (const id of ['first', 'second']) {
            window.SSHGatewayDialog.prepare({username: 'user:target', client_request_id: id}, id === 'second');
            dispatch('ssh_gateway_progress', {client_request_id: id, phase: 'setup'});
        }
        dispatch('quick_connect_error', {client_request_id: 'second', error: 'Cancelled'});
    });
    const modal = page.locator('#sshGatewayModal');
    await expect(modal).toHaveClass(/show/);
    await expect(modal.locator('.xterm')).toHaveCount(1);
    await modal.locator('.xterm-helper-textarea').press('y');
    await expect.poll(() => page.evaluate(() => window.__gatewayInputs)).toEqual([
        {client_request_id: 'first', data: 'y'},
    ]);
    await page.evaluate(() => window.SSHGatewayDialog.close('first'));
    await expect(modal).not.toHaveClass(/show/);
    await expect(modal.locator('.xterm')).toHaveCount(0);
});

test('concurrent gateway challenges keep their answers scoped and clear on disconnect', async ({page}) => {
    await login(page);
    await page.evaluate(() => {
        window.__answers = [];
        const original = window.socket.emit.bind(window.socket);
        window.socket.emit = (event, data, ack) => {
            if (event === 'ssh_gateway_answer') {
                window.__answers.push(data);
                ack?.({success: true});
                return;
            }
            return original(event, data, ack);
        };
        window.SSHGatewayDialog.prepare({username: 'user:target', client_request_id: 'first'});
        window.socket.listeners('ssh_gateway_challenge').forEach(fn => fn({
            client_request_id: 'first', challenge_id: 'first-otp', prompts: [{label: 'First OTP'}],
        }));
    });
    const modal = page.locator('#sshGatewayModal');
    await modal.locator('input').fill('123456');
    await page.evaluate(() => {
        window.SSHGatewayDialog.prepare({username: 'user:target', client_request_id: 'second'});
        window.socket.listeners('ssh_gateway_challenge').forEach(fn => fn({
            client_request_id: 'second', challenge_id: 'second-otp', prompts: [{label: 'Second OTP'}],
        }));
    });
    await expect(modal.locator('input')).toHaveValue('');
    await page.evaluate(() => window.SSHGatewayDialog.close('second'));
    await expect(modal.locator('input')).toHaveValue('123456');
    await modal.locator('button[type=submit]').click();
    expect(await page.evaluate(() => window.__answers)).toEqual([
        {client_request_id: 'first', challenge_id: 'first-otp', answers: ['123456']},
    ]);
    await page.evaluate(() => window.socket.listeners('disconnect').forEach(fn => fn('transport close')));
    await expect(modal).not.toHaveClass(/show/);
    await expect(modal.locator('input')).toHaveCount(0);
    expect(await page.evaluate(() => window.SSHGatewayDialog.has('first'))).toBe(false);
});

for (const outcome of ['declined', 'timed out']) {
    test(`pending gateway terminal returns after another SSH banner is ${outcome}`, async ({page}) => {
        await login(page);
        await page.evaluate(() => {
            const dispatch = (event, data) => window.socket.listeners(event).forEach(fn => fn(data));
            window.__gatewayInputs = [];
            const original = window.socket.emit.bind(window.socket);
            window.socket.emit = (event, data, ...args) => {
                if (event === 'ssh_gateway_input') {
                    window.__gatewayInputs.push(data);
                    return;
                }
                if (event === 'ssh_auth_banner_decision') {
                    dispatch('ssh_error', {client_request_id: 'reconnect_second', error: 'Banner declined'});
                    return;
                }
                return original(event, data, ...args);
            };
            for (const id of ['reconnect_first', 'reconnect_second', 'reconnect_third']) {
                window.SSHGatewayDialog.prepare({username: 'user:target', client_request_id: id});
            }
            dispatch('ssh_gateway_progress', {client_request_id: 'reconnect_first', phase: 'setup'});
            dispatch('ssh_gateway_challenge', {
                client_request_id: 'reconnect_second', challenge_id: 'otp', prompts: [{label: 'OTP'}],
            });
            dispatch('ssh_auth_banner', {
                client_request_id: 'reconnect_second', prompt_id: 'banner',
                banner: 'Access policy', host: 'gateway.local', port: 22,
            });
            // An unrelated failure must not bring a gateway prompt above this banner.
            dispatch('ssh_error', {client_request_id: 'reconnect_third', error: 'Connection failed'});
        });
        const gateway = page.locator('#sshGatewayModal');
        const banner = page.locator('#sshAuthBannerModal');
        await expect(banner).toHaveClass(/show/);
        await expect(gateway).not.toHaveClass(/show/);
        if (outcome === 'declined') {
            await page.locator('#sshAuthBannerCancel').click();
        } else {
            await page.evaluate(() => window.socket.listeners('ssh_error').forEach(fn => fn({
                client_request_id: 'reconnect_second', error: 'Banner timed out',
            })));
        }
        await expect(banner).not.toHaveClass(/show/);
        await expect(gateway).toHaveClass(/show/);
        await expect(gateway.locator('.xterm')).toHaveCount(1);
        await gateway.locator('.xterm-helper-textarea').press('y');
        await expect.poll(() => page.evaluate(() => window.__gatewayInputs)).toEqual([
            {client_request_id: 'reconnect_first', data: 'y'},
        ]);
        await page.evaluate(() => window.socket.listeners('disconnect').forEach(fn => fn('transport close')));
        await expect(gateway).not.toHaveClass(/show/);
        await expect(gateway.locator('.xterm')).toHaveCount(0);
    });
}

test('gateway backdrop click preserves the prompt and its cancel action', async ({page}) => {
    await login(page);
    await page.evaluate(() => {
        window.SSHGatewayDialog.prepare({username: 'user:target', client_request_id: 'backdrop'});
        window.socket.listeners('ssh_gateway_challenge').forEach(fn => fn({
            client_request_id: 'backdrop', challenge_id: 'otp', prompts: [{label: 'OTP'}],
        }));
    });
    const modal = page.locator('#sshGatewayModal');
    await modal.locator('input').fill('123456');
    await modal.click({position: {x: 2, y: 2}});
    await expect(modal).toHaveClass(/show/);
    await expect(modal.locator('input')).toHaveValue('123456');
    await expect(modal.locator('.btn-secondary')).toBeVisible();
    await page.evaluate(() => window.SSHGatewayDialog.close('backdrop'));
    await expect(modal.locator('input')).toHaveCount(0);
});


for (const action of ['button', 'escape']) {
    test(`gateway direct reconnect can be cancelled using ${action}`, async ({page}) => {
        await login(page);
        await page.evaluate(() => {
            window.__gatewayCancels = [];
            const original = window.socket.emit.bind(window.socket);
            window.socket.emit = (event, data, ack) => {
                if (event === 'ssh_connect_cancel') {
                    window.__gatewayCancels.push(data.client_request_id);
                    ack?.({success: true, cancelled: true});
                    return;
                }
                return original(event, data, ack);
            };
            window.SSHGatewayDialog.prepare({username: 'user:target', client_request_id: 'reconnect_test'});
            window.socket.listeners('ssh_gateway_challenge').forEach(fn => fn({
                client_request_id: 'reconnect_test', challenge_id: 'otp', prompts: [{label: 'OTP'}],
            }));
        });
        const modal = page.locator('#sshGatewayModal');
        await expect(modal).toHaveClass(/show/);
        if (action === 'escape') await modal.locator('input').press('Escape');
        else await modal.locator('.btn-secondary').click();
        await expect(modal).not.toHaveClass(/show/);
        expect(await page.evaluate(() => window.__gatewayCancels)).toEqual(['reconnect_test']);
    });
}


test('quick gateway errors and disconnect release only the matching request', async ({page}) => {
    await login(page);
    const result = await page.evaluate(() => {
        const manager = window.getSFTPFileManager();
        const dispatch = (event, data) => window.socket.listeners(event).forEach(fn => fn(data));
        manager.gatewayQuickRequestId = 'new-request';
        dispatch('quick_connect_error', {client_request_id: 'old-request', error: 'Invalid host'});
        const afterOld = manager.gatewayQuickRequestId;
        dispatch('quick_connect_error', {client_request_id: 'new-request', error: 'Invalid host'});
        const afterCurrent = manager.gatewayQuickRequestId;
        manager.gatewayQuickRequestId = 'retry';
        dispatch('disconnect', 'transport close');
        return {afterOld, afterCurrent, afterDisconnect: manager.gatewayQuickRequestId};
    });
    expect(result).toEqual({afterOld: 'new-request', afterCurrent: null, afterDisconnect: null});
});

test('ordinary SSH prepares masked PAM prompts with gateway disabled', async ({page}) => {
    await loginDefault(page);
    const payload = await page.evaluate(() => {
        const payload = {username: 'alice', auth_type: 'password', client_request_id: 'pam-test'};
        window.SSHGatewayDialog.prepare(payload);
        window.socket.listeners('ssh_gateway_challenge').forEach(fn => fn({
            client_request_id: 'pam-test', challenge_id: 'otp', title: 'SSH authentication',
            instructions: 'Enter your verification code', prompts: [{label: 'Verification code:'}],
        }));
        return payload;
    });
    expect(payload.ssh_interaction).toBe(1);
    expect(payload.gateway_interaction).toBeUndefined();
    const modal = page.locator('#sshGatewayModal');
    await expect(modal).toHaveClass(/show/);
    await expect(modal.locator('input')).toHaveAttribute('type', 'password');
    await expect(modal).toContainText('Verification code:');
    await expect(modal.locator('#sshGatewayTitle')).toHaveText('SSH authentication');
});
