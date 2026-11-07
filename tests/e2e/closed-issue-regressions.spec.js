const {test, expect} = require('playwright/test');
const fs = require('node:fs/promises');
const {login, openProfileManagement, assertNoExternalRequests} = require('./helpers');

for (const layout of ['single', 'split']) {
    for (const kind of ['sftp', 'smb']) {
        test(`issue 143: closing final ${kind} source clears rows in ${layout} layout`, async ({page}) => {
            await login(page);
            await page.evaluate(({layout, kind}) => {
                openFileManager();
                const manager = window.sftpFileManager;
                manager.closeSourceLauncher();
                const source = manager.normalizeSourceDescriptor({
                    source_id: `${kind}-quick:closed-issue-fixture`, kind,
                    label: 'Disposable fixture', endpoint: 'fixture.invalid', protocol: kind.toUpperCase(),
                    capabilities: ['list', 'read', 'write', 'rename', 'delete'],
                    ephemeral: false, security: {host_key_verified: true, encrypted: true},
                });
                const state = manager.createEmptyPaneState();
                Object.assign(state, {source, path: '/', files: [{name: 'must-disappear.txt', size: 10, is_dir: false}],
                    loading: false, selected: new Set(), autoHomeEligible: false});
                manager.workspace.openTab('left', source, state);
                manager.syncPaneFromWorkspace('left');
                manager.renderPane('left');
                manager.renderWorkspaceChrome();
                document.getElementById(layout === 'split' ? 'fmLayoutSplit' : 'fmLayoutSingle').click();
            }, {layout, kind});
            await expect(page.locator('#fmLeftList')).toContainText('must-disappear.txt');
            await page.locator('#fmLeftTabs .fm-source-tab-close').click();
            await expect(page.locator('#fmLeftTabs .fm-source-tab')).toHaveCount(0);
            await expect(page.locator('#fmLeftList')).not.toContainText('must-disappear.txt');
            await expect(page.locator('#fmLeftList .fm-file-item')).toHaveCount(0);
            await expect(page.locator('#fmTransfer')).toBeDisabled();
            await expect.poll(() => page.evaluate(() => window.sftpFileManager.panes.left.files.length)).toBe(0);
            await assertNoExternalRequests(page);
        });
    }
}

for (const width of [390, 1440]) {
    test(`issue 180: saved-host tmux follows administrator setting at ${width}px`, async ({page}) => {
        await page.setViewportSize({width, height: 900});
        await login(page);
        await openProfileManagement(page);
        await page.locator('#newProfileBtn').click();
        const option = page.locator('#profileEditorUseTmux');
        if (process.env.TMUX_ENABLED !== 'true') {
            await expect(option).toHaveCount(0);
            return;
        }
        await page.locator('#profileEditorName').fill(`Tmux regression ${width}`);
        await page.locator('#profileEditorHost').fill('fixture.invalid');
        await page.locator('#profileEditorUsername').fill('test');
        const details = option.locator('xpath=ancestor::details');
        await details.locator('summary').click();
        await expect(option).toBeVisible();
        await option.check();
        await page.locator('#profileEditorForm button[type="submit"]').first().click();
        await expect.poll(() => page.evaluate(name => ProfileManager.profiles.find(p => p.name === name)?.use_tmux, `Tmux regression ${width}`)).toBe(true);
        await page.reload();
        await expect.poll(() => page.evaluate(name => ProfileManager.profiles.find(p => p.name === name)?.use_tmux, `Tmux regression ${width}`)).toBe(true);
        await openProfileManagement(page);
        await page.locator('.profile-management-item').filter({hasText: `Tmux regression ${width}`}).locator('.profile-inspect-button').click();
        if (!await option.isVisible()) await option.locator('xpath=ancestor::details').locator('summary').click();
        await expect(option).toBeChecked();
        await option.uncheck();
        await page.locator('#profileEditorForm button[type="submit"]').first().click();
        await expect.poll(() => page.evaluate(name => ProfileManager.profiles.find(p => p.name === name)?.use_tmux, `Tmux regression ${width}`)).toBe(false);
        await assertNoExternalRequests(page);
    });

    test(`issue 240: transcript download contains complete clean lines at ${width}px`, async ({page}) => {
        await page.setViewportSize({width, height: 900});
        await login(page);
        await page.evaluate(() => {
            const original = window.socket.emit.bind(window.socket);
            window.socket.emit = function(event, payload, ...args) {
                if (payload?.session_id === 'transcript-fixture' || String(payload?.source_id).includes('transcript-fixture')) return this;
                return original(event, payload, ...args);
            };
            SessionManager.createSession({session_id: 'transcript-fixture', host: 'fixture.invalid', username: 'test', port: 22});
            SessionManager.assignSessionToPane('transcript-fixture', 0);
            TerminalManager.writeOutput('transcript-fixture', '\x1b[32mfirst line\x1b[0m\r\nsecond line\r\n');
        });
        await expect.poll(() => page.evaluate(() => TerminalManager.getCleanTranscript('transcript-fixture'))).toContain('second line');
        const downloaded = page.waitForEvent('download');
        if (width < 768) {
            await page.locator('#mobileMoreBtn').click();
            await page.locator('#mobileTranscriptAction').click();
        } else {
            await page.locator('#saveTranscriptBtn').click();
        }
        const download = await downloaded;
        expect(download.suggestedFilename()).toBe('session-transcript-fixture.txt');
        const contents = await fs.readFile(await download.path(), 'utf8');
        expect(contents).toBe('first line\nsecond line\n');
        await assertNoExternalRequests(page);
    });
}
