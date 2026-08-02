const { expect } = require('playwright/test');
const e2ePort = process.env.WEBSSH_E2E_PORT || '4173';
const allowedLocalHost = new URL(`http://127.0.0.1:${e2ePort}`).host;

function installExternalRequestGuard(page) {
    const externalRequests = [];
    page.on('request', request => {
        const url = new URL(request.url());
        if (!['http:', 'ws:', 'data:', 'blob:'].includes(url.protocol)) {
            externalRequests.push(request.url());
            return;
        }
        if (['http:', 'ws:'].includes(url.protocol)
                && url.host !== allowedLocalHost) {
            externalRequests.push(request.url());
        }
    });
    page.__externalRequests = externalRequests;
}

async function login(page, username = 'e2e_admin') {
    installExternalRequestGuard(page);

    await page.goto('/login');
    await page.locator('#username').fill(username);
    await page.locator('#password').fill('browser-password');
    await page.locator('form button[type="submit"]').click();
    await expect(page).toHaveURL(/\/$/);
    await expect.poll(() => page.evaluate(() => (
        window.ProfileManager?.profilesLoaded === true
        && Array.isArray(window.JumpHostManager?.jumpHosts)
    ))).toBe(true);
}

async function installSshConnectTrap(page) {
    await page.evaluate(() => {
        if (window.__sshConnectOriginalEmit) {
            window.socket.emit = window.__sshConnectOriginalEmit;
        }
        const originalEmit = window.socket.emit.bind(window.socket);
        window.__sshConnectOriginalEmit = originalEmit;
        window.__sshConnectAttempts = [];
        window.socket.emit = function wrappedEmit(event, ...args) {
            if (event !== 'ssh_connect') {
                return originalEmit(event, ...args);
            }

            const acknowledgement = typeof args.at(-1) === 'function'
                ? args.pop()
                : null;
            const payload = structuredClone(args[0]);
            window.__sshConnectAttempts.push({
                payload,
                hadAcknowledgement: Boolean(acknowledgement),
            });

            queueMicrotask(() => {
                if (acknowledgement) {
                    acknowledgement({
                        success: false,
                        error: 'E2E intercepted local SSH connect',
                    });
                    return;
                }
                window.socket.listeners('ssh_error').forEach(listener => listener({
                    error: 'E2E intercepted local SSH connect',
                    client_request_id: payload.client_request_id,
                }));
            });
            return window.socket;
        };
    });
}

async function sshAttempts(page) {
    return page.evaluate(() => window.__sshConnectAttempts || []);
}

async function restoreSshConnect(page) {
    await page.evaluate(() => {
        if (window.__sshConnectOriginalEmit) {
            window.socket.emit = window.__sshConnectOriginalEmit;
            delete window.__sshConnectOriginalEmit;
        }
        window.__sshConnectAttempts = [];
    });
}

async function openProfileManagement(page) {
    await page.locator('#manageProfilesBtn').click();
    await expect(page.locator('#profileManagementModal')).toHaveClass(/show/);
    await expect(page.locator('#profileManagementView')).not.toHaveClass(/hidden/);
}

async function launchProfile(page, name) {
    const exactName = new RegExp(`^${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`);
    const card = page.locator('.profile-launcher-card').filter({
        has: page.locator('.profile-launcher-name', { hasText: exactName }),
    });
    await expect(card).toHaveCount(1);
    await card.click();
}

async function assertNoExternalRequests(page) {
    expect(page.__externalRequests || []).toEqual([]);
}

module.exports = {
    assertNoExternalRequests,
    installExternalRequestGuard,
    installSshConnectTrap,
    launchProfile,
    login,
    openProfileManagement,
    restoreSshConnect,
    sshAttempts,
};
