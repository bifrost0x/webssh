const {test,expect}=require('playwright/test');
const {login,assertNoExternalRequests}=require('./helpers');

test('tool labels and note text remain readable across all themes', async ({page}) => {
    await login(page);
    for (const theme of ['glass','werkbank','retro','solar','paper','noir','arctic-ice','rose-gold','cyberpunk-neon','emerald-matrix','obsidian']) {
        await page.evaluate(value => applyTheme(value), theme);
        await page.evaluate(() => workspaceLayoutController.openContext('notes','user'));
        for (const width of [360,3440]) {
            await page.setViewportSize({width,height:900});
            await page.evaluate(() => workspaceLayoutController.openContext('notes','user'));
            const values = await page.evaluate(() => {
                const ctx = document.createElement('canvas').getContext('2d', {willReadFrequently:true});
                const rgba = color => {ctx.clearRect(0,0,1,1);ctx.fillStyle=color;ctx.fillRect(0,0,1,1);return [...ctx.getImageData(0,0,1,1).data];};
                const background = el => {
                    const c=rgba(getComputedStyle(el).backgroundColor);
                    const below=el.parentElement ? background(el.parentElement) : [255,255,255];
                    return c.slice(0,3).map((v,i)=>v*c[3]/255+below[i]*(1-c[3]/255));
                };
                const luminance = c => c.slice(0,3).map(v=>v/255).map(v=>v<=.04045?v/12.92:((v+.055)/1.055)**2.4).reduce((s,v,i)=>s+v*[.2126,.7152,.0722][i],0);
                return ['#contextNotesTab','#contextCommandsTab','#sessionNotepad','[data-i18n="workspaceContext.notesHint"]'].map(selector=>{
                    const el=document.querySelector(selector);
                    const fg=luminance(rgba(getComputedStyle(el).color));
                    const bg=luminance(background(el));
                    return {selector,ratio:(Math.max(fg,bg)+.05)/(Math.min(fg,bg)+.05)};
                });
            });
            for (const value of values) expect.soft(value.ratio,`${theme} ${width} ${value.selector}`).toBeGreaterThanOrEqual(4.5);
        }
    }
    await assertNoExternalRequests(page);
});
