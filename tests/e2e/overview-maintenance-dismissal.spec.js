const {test,expect}=require('playwright/test');
const {login,installSshConnectTrap,assertNoExternalRequests}=require('./helpers');
async function preferences(page,dismissed) {
    const response=await page.request.put('/api/overview/preferences',{data:{dismissed},headers:{'X-CSRFToken':await page.locator('meta[name="csrf-token"]').getAttribute('content')}});
    expect(response.ok()).toBe(true);
}
async function maintenance(page) {
    await expect.poll(()=>page.evaluate(()=>window.ProfileManager?.profilesLoaded===true)).toBe(true);
    return page.evaluate(()=>{
        const profile=window.ProfileManager.profiles[0];
        profile.name='Node';
        profile.detected_maintenance={reboot_required:true,updates:3,security_updates:2,checked_at:Date.now()/1000};
        window.dispatchEvent(new Event('profile-list-change'));
        return profile.id;
    });
}
test.afterEach(async({page})=>{
    await preferences(page,[]);
    await assertNoExternalRequests(page);
});
for(const width of [1440,390])test(`maintenance dismissal persists via the real API at ${width}px`,async({page})=>{
    await page.setViewportSize({width,height:900});
    await login(page,'e2e_admin',{workspace:false});
    const previous=['run-failed:existing','host-keys:existing'];
    await preferences(page,previous);
    await page.reload();
    const hostId=await maintenance(page);
    await installSshConnectTrap(page);
    const expected=[...previous];
    for(const kind of ['reboot','security-updates']){
        const key=`${kind}:${hostId}`;
        const dismiss=page.locator(`#odAttention [data-key="dismiss:${key}"]`);
        await expect(dismiss).toBeVisible();
        const saved=page.waitForResponse(response=>response.url().endsWith('/api/overview/preferences')&&response.request().method()==='PUT');
        await dismiss.click();
        const response=await saved;expect(response.status()).toBe(200);
        expected.push(key);expect((await response.json()).dismissed).toEqual(expected);
        await expect(dismiss).toHaveCount(0);
        await expect(page.locator('#odAttentionError')).toBeHidden();
    }
    expect(await page.evaluate(()=>window.__sshConnectAttempts.length)).toBe(0);
    await page.reload();
    await maintenance(page);
    for(const kind of ['reboot','security-updates'])await expect(page.locator(`#odAttention [data-key="dismiss:${kind}:${hostId}"]`)).toHaveCount(0);
    expect(await page.locator('#overviewPreferences').evaluate(node=>JSON.parse(node.textContent).dismissed)).toEqual(expected);
    await page.locator('#odAttentionRestore').click();
    for(const kind of ['reboot','security-updates'])await expect(page.locator(`#odAttention [data-key="dismiss:${kind}:${hostId}"]`)).toBeVisible();
});
