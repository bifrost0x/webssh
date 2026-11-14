const {test, expect} = require('playwright/test');
const {login, installSshConnectTrap} = require('./helpers');

test('workspace presets survive reload and require explicit host connection', async ({page}) => {
    await login(page);
    await installSshConnectTrap(page);
    await page.evaluate(()=>Object.defineProperty(window.crypto,'randomUUID',{value:undefined,configurable:true}));
    await page.locator('#workspacePresetsBtn').click();
    const dialog=page.getByRole('dialog', {name:'Workspace presets',exact:true});
    await expect(dialog).toBeVisible();
    await dialog.getByLabel('Preset name',{exact:true}).fill('Daily operations');
    await dialog.getByLabel('Panes',{exact:true}).selectOption('2');
    await dialog.getByLabel('Password review',{exact:true}).check();
    await dialog.getByRole('button',{name:'Save preset',exact:true}).click();
    const preset=dialog.locator('section').filter({has:page.getByRole('heading',{name:'Daily operations',exact:true})});
    await expect(preset).toBeVisible();
    await preset.getByRole('button',{name:'Apply layout and choose connections',exact:true}).click();
    expect(await page.evaluate(()=>SessionManager.layout)).toBe(2);
    expect(await page.evaluate(()=>window.__sshConnectAttempts.length)).toBe(0);
    await expect(preset.getByRole('button',{name:'Connect Password review',exact:true})).toBeVisible();
    await dialog.getByRole('button',{name:'Close',exact:true}).click();
    await page.reload();
    await page.locator('#workspaceNavBtn').click();
    await page.locator('#workspacePresetsBtn').click();
    await expect(page.getByRole('dialog').getByRole('heading',{name:'Daily operations',exact:true})).toBeVisible();
    await page.getByRole('dialog').locator('section').filter({has:page.getByRole('heading',{name:'Daily operations',exact:true})}).getByRole('button',{name:'Remove preset',exact:true}).click();
    await expect(page.getByRole('dialog').getByRole('heading',{name:'Daily operations',exact:true})).toHaveCount(0);
});

test('recovery guidance names omitted credentials and current owned hosts on mobile', async ({page})=>{
    await page.setViewportSize({width:390,height:844});
    await login(page,'e2e_user');
    await page.evaluate(()=>document.querySelector('[data-recovery-check]').click());
    const dialog=page.getByRole('dialog',{name:'Recovery check',exact:true});
    await expect(dialog).toBeVisible();
    await expect(dialog.locator('.customer-disclosure')).not.toHaveAttribute('open','');
    await dialog.getByText('Backup coverage',{exact:true}).click();
    await expect(dialog.getByText(/Portable backups exclude/)).toBeVisible();
    await expect(dialog.getByText('Unauthorized Tailscale',{exact:true})).toBeVisible();
    await expect(dialog.getByText('Password review',{exact:true})).toHaveCount(0);
    expect(await dialog.evaluate(node=>node.scrollWidth<=node.clientWidth)).toBe(true);
    await dialog.getByRole('button',{name:'Close',exact:true}).click();
});

test('session lifecycle explicitly separates transport recovery and normal SSH lifetime',async({page})=>{
    await login(page);
    await page.evaluate(()=>{
        const session={id:'continuity-fixture',host:'synthetic.example',username:'operator',connected:true,useTmux:false};
        SessionManager.sessions[session.id]=session;
        SessionManager.activeSessionId=session.id;
        SessionManager.getWorkspaceSession=()=>session.id;
        window.dispatchEvent(new Event('session-workspace-change'));
    });
    await expect(page.locator('#workspaceContinuity')).toContainText('Normal SSH');
    await page.evaluate(()=>{SessionManager.sessions['continuity-fixture'].useTmux=true;window.dispatchEvent(new Event('session-workspace-change'));});
    await expect(page.locator('#workspaceContinuity')).toContainText('tmux');
    await page.evaluate(()=>{delete SessionManager.sessions['continuity-fixture'];SessionManager.activeSessionId=null;window.dispatchEvent(new Event('session-workspace-change'));});
    await expect(page.locator('#workspaceContinuity')).toBeHidden();
});
