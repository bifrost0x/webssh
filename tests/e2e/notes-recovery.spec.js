const {test,expect}=require('playwright/test');
const {login,assertNoExternalRequests}=require('./helpers');

for (const width of [360,1280]) test(`failed notes can retry unchanged text at ${width}px`,async({page},testInfo)=>{
    await page.setViewportSize({width,height:800});
    await login(page);
    await page.evaluate(()=>{
        const emit=socket.emit.bind(socket);
        window.__noteWrites=[];
        socket.emit=(event,data,ack)=>{
            if(event!=='save_notepad') return emit(event,data,ack);
            window.__noteWrites.push(data.text);
            if(window.__noteWrites.length===1) queueMicrotask(()=>ack({success:false}));
            else window.__finishNoteSave=()=>ack({success:true});
            return socket;
        };
        workspaceLayoutController.openContext('notes','user');
    });
    const notes=page.locator('#sessionNotepad');
    const retry=page.locator('#notepadRetryBtn');
    await notes.fill('Keep this exact note');
    await expect(page.locator('#notepadSaveStatus')).toHaveClass(/failed/);
    await expect(retry).toBeVisible();
    await expect(retry).toBeInViewport();
    const panelBox=await page.locator('#contextNotesPanel').boundingBox();
    const editorBox=await notes.boundingBox();
    expect(panelBox.y+panelBox.height-editorBox.y-editorBox.height).toBeLessThanOrEqual(24);
    if (width === 360) {
        for (const language of ['de','fr','vi','es','zh','en']) {
            await page.evaluate(value=>i18n.setLanguage(value),language);
            await expect(retry).toBeInViewport();
            expect(await retry.evaluate(el=>el.scrollWidth<=el.clientWidth)).toBe(true);
            expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
        }
        expect((await retry.boundingBox()).height).toBeGreaterThanOrEqual(44);
    }
    await page.screenshot({path:testInfo.outputPath(`notes-retry-${width}.png`),animations:'disabled'});
    await retry.click();
    await expect(retry).toBeHidden();
    expect(await page.evaluate(()=>window.__noteWrites)).toEqual(['Keep this exact note','Keep this exact note']);
    await page.evaluate(()=>window.__finishNoteSave());
    await expect(page.locator('#notepadSaveStatus')).toHaveText('Saved');
    await expect(notes).toHaveValue('Keep this exact note');
    await expect(notes).toBeFocused();
    expect(await page.evaluate(()=>notepadController.hasUnsaved())).toBe(false);
    expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
    await assertNoExternalRequests(page);
});
