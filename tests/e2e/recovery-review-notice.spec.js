const {test,expect}=require('playwright/test');
const {login,installSshConnectTrap,sshAttempts}=require('./helpers');

// UI state transitions use a bounded fake recovery response; real account
// persistence, stale markers and CSRF are covered by test_recovery_review.py.
async function recoveryEndpoint(page, initial='2026-11-14T06:00:00+00:00') {
    const state={marker:initial,reviewed:null,posts:[]};
    await page.route('**/api/account/recovery-check',async route=>{
        if(route.request().method()==='POST') {
            const body=route.request().postDataJSON();state.posts.push(body);
            expect(route.request().headers()['x-csrftoken']).toBeTruthy();
            if(body.restored_at!==state.marker)return route.fulfill({status:409,json:{code:'restore_changed'}});
            state.reviewed=body.restored_at;
            return route.fulfill({json:{restored_at:state.marker,needs_review:false}});
        }
        return route.fulfill({json:{restored_at:state.marker,needs_review:Boolean(state.marker&&state.marker!==state.reviewed),hosts:[],schedules:[],coverage:{remote_credentials:'excluded'}}});
    });
    return state;
}

for(const width of [390,1440]) {
    test(`post-restore notice opens centered checklist and review persists on reload at ${width}px`,async({page},info)=>{
        await page.setViewportSize({width,height:900});
        const state=await recoveryEndpoint(page);
        await login(page,'e2e_admin',{workspace:false});
        await installSshConnectTrap(page);
        const notice=page.locator('#restoreRecoveryNotice');
        await expect(notice).toBeVisible();
        await page.screenshot({path:info.outputPath(`recovery-notice-${width}.png`),animations:'disabled'});
        await notice.getByRole('button',{name:'Open recovery checklist'}).click();
        const dialog=page.locator('dialog.customer-dialog');
        await expect(dialog).toBeVisible();
        await expect(dialog).toContainText('only dismisses this reminder for your account');
        await expect(dialog).toContainText('does not verify recovery');
        const box=await dialog.boundingBox();
        expect(Math.abs(box.x+box.width/2-width/2)).toBeLessThan(3);
        expect(Math.abs(box.y+box.height/2-450)).toBeLessThan(3);
        expect(await dialog.evaluate(el=>el.scrollWidth<=el.clientWidth+1)).toBe(true);
        await page.screenshot({path:info.outputPath(`recovery-dialog-${width}.png`),animations:'disabled'});
        expect(state.posts).toEqual([]);
        expect(await sshAttempts(page)).toEqual([]);
        await dialog.getByRole('button',{name:'Mark recovery steps reviewed'}).click();
        await expect(dialog).toHaveCount(0);await expect(notice).toBeHidden();
        expect(state.posts).toEqual([{restored_at:state.marker}]);
        await page.reload();await expect(notice).toBeHidden();
        state.marker='2026-11-14T06:01:00+00:00';
        await page.reload();await expect(notice).toBeVisible();
    });
}

test('a new restore rejects the old checklist and requires fresh review',async({page})=>{
    const state=await recoveryEndpoint(page);
    await login(page,'e2e_admin',{workspace:false});
    await page.locator('#restoreRecoveryNotice button').click();
    const dialog=page.locator('dialog.customer-dialog');
    await expect(dialog.getByRole('button',{name:'Mark recovery steps reviewed'})).toBeVisible();
    state.marker='2026-11-14T06:01:00+00:00';
    await dialog.getByRole('button',{name:'Mark recovery steps reviewed'}).click();
    await expect(dialog.getByRole('alert')).toContainText('Another restore occurred');
    await expect(page.locator('#restoreRecoveryNotice')).toBeVisible();
    expect(state.reviewed).toBeNull();
    await dialog.getByRole('button',{name:'Reload recovery checklist'}).click();
    await expect(page.locator('dialog.customer-dialog').getByRole('button',{name:'Mark recovery steps reviewed'})).toBeEnabled();
    await page.locator('dialog.customer-dialog').getByRole('button',{name:'Mark recovery steps reviewed'}).click();
    await expect(page.locator('#restoreRecoveryNotice')).toBeHidden();
    expect(state.reviewed).toBe(state.marker);
});

test('without a restore marker the optional manual checklist has no review reminder',async({page})=>{
    const state=await recoveryEndpoint(page,null);
    await login(page,'e2e_admin',{workspace:false});
    await expect(page.locator('#restoreRecoveryNotice')).toBeHidden();
    await page.evaluate(()=>document.querySelector('[data-recovery-check]').click());
    await expect(page.locator('dialog.customer-dialog')).toContainText('No saved hosts');
    await expect(page.locator('[data-review-recovery]')).toHaveCount(0);
    expect(state.posts).toEqual([]);
});
