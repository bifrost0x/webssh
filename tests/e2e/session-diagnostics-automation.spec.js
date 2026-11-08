const {test,expect}=require('playwright/test');
const {login,assertNoExternalRequests}=require('./helpers');

test('host diagnostics selects exact target history and opens its full run log',async({page},testInfo)=>{
    const errors=[];page.on('pageerror',error=>errors.push(error.message));
    const step={name:'Package update',status:'failed',exit_code:1,duration:0.75,reason:'nonzero_exit',stdout:'host-a captured output',stderr:'confirmation required',output_truncated:false};
    const target={id:'profile-a',name:'Host A',host:'host-a.invalid',port:22,username:'ops',status:'failed',steps:[step]};
    const runs=[
        {id:'exact-run',name:'Host A maintenance',created_at:'2026-11-04T10:00:00Z',status:'failed',targets:[target]},
        {id:'other-profile',name:'Same endpoint different profile',created_at:'2026-11-04T11:00:00Z',status:'failed',targets:[{...target,id:'profile-other'}]},
        {id:'old-endpoint',name:'Previous endpoint result',created_at:'2026-11-04T12:00:00Z',status:'failed',targets:[{...target,host:'old.invalid'}]},
        {id:'second-host',name:'Host B maintenance',created_at:'2026-11-04T13:00:00Z',status:'failed',targets:[{...target,id:'profile-b',host:'host-b.invalid'}]},
    ];
    await page.route('**/api/automation/runs',route=>route.fulfill({json:{runs}}));
    await login(page);
    await page.evaluate(()=>{
        const original=window.socket.emit.bind(window.socket);
        window.socket.emit=function(event,payload,...rest){
            if(payload?.session_id?.startsWith('diagnostic-')){
                if(event==='request_session_insights')queueMicrotask(()=>window.socket.listeners('session_insights').forEach(listener=>listener({success:true,session_id:payload.session_id,request_id:payload.request_id,stats:{os_name:'Debian',memory:{total_kib:1024,available_kib:512,used_kib:512}}})));
                return window.socket;
            }
            return original(event,payload,...rest);
        };
        window.seedDiagnosticHost=(id,profile,host)=>{
            SessionManager.createSession({session_id:id,profile_id:profile,host,port:22,username:'ops'});
            SessionManager.assignSessionToPane(id,0);
        };
        window.seedDiagnosticHost('diagnostic-a','profile-a','host-a.invalid');
    });
    await expect(page.locator('#contextDiagnosticsTab')).toBeEnabled();
    await page.locator('#contextDiagnosticsTab').click();
    const section=page.locator('#sessionDiagnosticsAutomation');
    await expect(section).toContainText('Host A maintenance');
    await expect(section.locator('.session-automation-run')).toHaveCount(1);
    await expect(section).not.toContainText('Previous endpoint');
    await expect(section).not.toContainText('different profile');
    await expect(section).toContainText('Exit code: 1');
    for(const width of [1440,390]){
        await page.setViewportSize({width,height:1000});
        if(width < 800) await page.getByRole('button',{name:'Open session tools'}).click();
        if(!await section.isVisible())await page.locator('#contextDiagnosticsTab').click();
        await section.scrollIntoViewIfNeeded();
        await page.screenshot({path:testInfo.outputPath(`host-runs-${width}.png`),animations:'disabled'});
        expect(await section.evaluate(element=>element.scrollWidth<=element.clientWidth+1)).toBe(true);
    }
    await page.setViewportSize({width:1440,height:1000});
    await section.getByRole('button',{name:'View full log'}).click();
    const exact=page.locator('.automation-run[data-run-id="exact-run"]');
    await expect(exact).toBeVisible();
    await expect(exact).toHaveAttribute('open','');
    await expect(exact.locator('.automation-run-diagnostic')).toHaveAttribute('open','');
    await expect(exact.locator('pre').first()).toHaveText('host-a captured output');
    await page.locator('#workspaceNavBtn').click();
    await page.evaluate(()=>window.seedDiagnosticHost('diagnostic-b','profile-b','host-b.invalid'));
    if(!await section.isVisible())await page.locator('#contextDiagnosticsTab').click();
    await expect(section).toContainText('Host B maintenance');
    await expect(section).not.toContainText('Host A maintenance');
    await page.evaluate(()=>window.seedDiagnosticHost('diagnostic-changed','profile-a','changed.invalid'));
    if(!await section.isVisible())await page.locator('#contextDiagnosticsTab').click();
    await expect(section).toContainText('No recent runs for this host.');
    expect(errors).toEqual([]);await assertNoExternalRequests(page);
});
