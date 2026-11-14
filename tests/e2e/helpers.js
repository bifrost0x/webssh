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

async function login(page, username = 'e2e_admin', {workspace = true, tour = 'acknowledged'} = {}) {
    installExternalRequestGuard(page);

    await page.goto('/login');
    await page.locator('#username').fill(username);
    await page.locator('#password').fill('browser-password');
    const tourState = page.waitForResponse(response => response.url().endsWith('/api/account/tour') && response.request().method() === 'GET');
    await page.locator('form button[type="submit"]').click();
    await expect(page).toHaveURL(/\/$/);
    if ((await (await tourState).json()).state === 'new') {
        await page.locator('.intro-tour').getByRole('button', {name: 'Skip tour', exact: true}).click();
        await expect(page.locator('.intro-tour')).toHaveCount(0);
    }
    if (tour === 'acknowledged') {
        const response = await page.request.post('/api/account/tour', {data:{state:'completed',acknowledged:true},headers:{'X-CSRFToken':await page.locator('meta[name="csrf-token"]').getAttribute('content')}});
        expect(response.ok()).toBe(true);
    }
    await waitForInventory(page);
    if (workspace) await openWorkspace(page);
}

async function waitForInventory(page) {
    await expect.poll(() => page.evaluate(() => (
        window.ProfileManager?.profilesLoaded === true
        && window.ProfileManager?.keysLoaded === true
        && window.JumpHostManager?.loaded === true
        && window.SocksProxyManager?.loaded === true
        && window.socket?.connected === true
        && Array.isArray(window.JumpHostManager?.jumpHosts)
    ))).toBe(true);
}

async function openWorkspace(page) {
    const desktopNav = page.locator('#workspaceNavBtn');
    const mobileNav = page.locator('.mobile-dock-item[data-mobile-view="workspaces"]');
    await (await desktopNav.isVisible() ? desktopNav : mobileNav).click();
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

async function observeConnectionModal(page) {
    await page.evaluate(() => {
        window.__connectionModalShows = 0;
        window.__connectionModalObserver?.disconnect();
        const modal = document.getElementById('connectionModal');
        window.__connectionModalObserver = new MutationObserver(() => {
            if (modal.classList.contains('show')) {
                window.__connectionModalShows += 1;
            }
        });
        window.__connectionModalObserver.observe(modal, {
            attributes: true,
            attributeFilter: ['class'],
        });
    });
}

async function installKeyUploadTrap(page) {
    await page.evaluate(() => {
        if (window.__keyUploadOriginalEmit) {
            window.socket.emit = window.__keyUploadOriginalEmit;
        }
        const originalEmit = window.socket.emit.bind(window.socket);
        window.__keyUploadOriginalEmit = originalEmit;
        window.__keyUploadAttempts = [];
        window.socket.emit = function wrappedEmit(event, ...args) {
            if (event !== 'upload_key') {
                return originalEmit(event, ...args);
            }
            const acknowledgement = typeof args.at(-1) === 'function'
                ? args.pop()
                : null;
            const payload = structuredClone(args[0]);
            window.__keyUploadAttempts.push(payload);
            queueMicrotask(() => acknowledgement?.({
                success: true,
                key: {
                    id: 'e2e-inline-key',
                    name: payload.name,
                    key_type: 'ED25519',
                    uploaded_at: new Date().toISOString(),
                },
            }));
            return window.socket;
        };
    });
}

async function keyUploadAttempts(page) {
    return page.evaluate(() => window.__keyUploadAttempts || []);
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

async function openResponsiveHeader(page, target) {
    if (await target.isVisible()) return;
    await page.locator('#mobileMoreBtn').click();
    await expect(target).toBeVisible();
}

async function openProfileManagement(page) {
    await waitForInventory(page);
    const trigger = page.locator('#manageProfilesBtn');
    await openResponsiveHeader(page, trigger);
    await trigger.click();
    await expect(page.locator('#profileManagementModal')).toHaveClass(/show/);
    await expect(page.locator('#profileManagementView')).not.toHaveClass(/hidden/);
}

async function openKeyManagement(page) {
    await openProfileManagement(page);
    await page.locator('#profileManagementModal [data-connection-asset="keys"]').click();
    await expect(page.locator('#keyManagementModal')).toHaveClass(/show/);
}

async function launchProfile(page, name) {
    const exactName = new RegExp(`^${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')},`);
    const card = page.getByRole('button', {name: exactName}).and(page.locator('.profile-launcher-card'));
    await expect(card).toHaveCount(1);
    await card.click();
}

async function assertNoExternalRequests(page) {
    expect(page.__externalRequests || []).toEqual([]);
}

async function assertRouteGeometry(page) {
    await expect.poll(() => page.locator('.ssh-route-canvas').evaluate(canvas => {
        const frame=canvas.getBoundingClientRect(), scale=Number(canvas.dataset.scale)||1;
        const paths=[...canvas.querySelectorAll(':scope > svg > path')];
        const targets=[...canvas.querySelectorAll('.ssh-route-branch')].flatMap(branch => {
            const source=branch.querySelector('.ssh-route-source');
            return source ? [source,branch.querySelector('.ssh-route-destinations')] : [branch.querySelector('.ssh-route-destinations')];
        });
        if(!targets.length || targets.length!==paths.length)return Infinity;
        const vertical=innerWidth<600 || (!canvas.closest('dialog') && canvas.parentElement.clientWidth<620);
        return Math.max(...targets.map((target,index)=>{
            const d=paths[index].getAttribute('d').split(' m ')[0];
            const values=d.match(/-?\d+(?:\.\d+)?(?:e[+-]?\d+)?/gi).map(Number);
            const elbow=d.includes(' H '), x=values.at(elbow?-1:-2), y=values.at(elbow?-2:-1);
            const r=target.getBoundingClientRect();
            const tx=vertical&&!elbow?r.left+r.width/2:r.left, ty=vertical&&!elbow?r.top:r.top+r.height/2;
            return Math.hypot(frame.left+x*scale-tx,frame.top+y*scale-ty);
        }));
    }), {message:'Every route arrow must end on its destination after layout changes'}).toBeLessThan(2);
}

module.exports = {
    assertRouteGeometry,
    openWorkspace,
    assertNoExternalRequests,
    installExternalRequestGuard,
    installKeyUploadTrap,
    installSshConnectTrap,
    keyUploadAttempts,
    launchProfile,
    login,
    waitForInventory,
    openKeyManagement,
    openProfileManagement,
    observeConnectionModal,
    restoreSshConnect,
    sshAttempts,
};
