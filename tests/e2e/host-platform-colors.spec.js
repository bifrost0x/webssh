const {test, expect} = require('playwright/test');
const fs = require('node:fs');
const path = require('node:path');
const {login}=require('./helpers');

test('Hosts management preserves platform colors in the actual host rows',async({page},info)=>{
 await login(page,'e2e_admin',{workspace:false});
 await page.evaluate(()=>ProfileManager.openManagement());
 // Finish the management refresh before installing the rendering fixture.
 await page.evaluate(() => new Promise(resolve => window.socket.emit('list_profiles', resolve)));
 await page.evaluate(()=>{const profile=ProfileManager.profiles[0];ProfileManager.setProfiles(['ubuntu','docker','proxmox','debian'].map(platform=>({...profile,id:platform,name:platform,platform_icon:platform})));});
 const icons=page.locator('#profileManagementList .profile-row-platform');await expect(icons).toHaveCount(4);
 for(const theme of ['glass','werkbank','retro','solar','paper','noir','arctic-ice','rose-gold','cyberpunk-neon','emerald-matrix','obsidian']){
  await page.evaluate(t=>document.body.dataset.theme=t,theme);
  const colors=await icons.evaluateAll(items=>items.map(icon=>{const reference=HostPlatform.render({platform_icon:icon.dataset.platform});document.body.append(reference);const actual=getComputedStyle(icon).color,expected=getComputedStyle(reference).color;reference.remove();return {actual,expected};}));
  for(const color of colors)expect(color.actual).toBe(color.expected);
  expect(new Set(colors.map(c=>c.actual)).size).toBe(4);
 }
 await page.screenshot({path:info.outputPath('hosts-colored.png')});
});

test('every platform retains contrast on every theme surface, including small session icons', async ({page}) => {
    const root = path.resolve(__dirname, '../..');
    const template = fs.readFileSync(path.join(root, 'templates/index.html'), 'utf8');
    const sheets = [...template.matchAll(/filename='(css\/[^']+\.css)'/g)].map(match => match[1]);
    await page.setContent('<body class="webssh-ui webssh-shell"></body>');
    for (const sheet of sheets) await page.addStyleTag({path: path.join(root, 'static', sheet)});
    await page.addScriptTag({path: path.join(root, 'static/js/host-platform.js')});
    for (const theme of ['glass', 'werkbank', 'retro', 'solar', 'paper', 'noir', 'arctic-ice', 'rose-gold', 'cyberpunk-neon', 'emerald-matrix', 'obsidian']) {
        const results = await page.evaluate(theme => {
            document.body.dataset.theme = theme;
            const luminance = color => color.match(/[\d.]+/g).slice(0, 3).map(Number).map(v => v / 255)
                .map(v => v <= .04045 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4)
                .reduce((sum, value, i) => sum + value * [.2126, .7152, .0722][i], 0);
            const results = [];
            for (const surface of ['canvas', 'surface', 'panel', 'raised', 'row-hover']) {
                for (const small of [false, true]) {
                    const holder = document.createElement('div');
                    holder.style.backgroundColor = `var(--ws2-${surface})`;
                    if (small) holder.className = 'session-platform-icon';
                    document.body.append(holder);
                    for (const platform of Object.keys(HostPlatform.labels)) {
                        const icon = HostPlatform.render({platform_icon: platform});
                        holder.append(icon);
                        const style = getComputedStyle(icon);
                        const fg = luminance(style.color);
                        const bg = luminance(getComputedStyle(holder).backgroundColor);
                        results.push({platform, surface, small, color: style.color, width: style.width,
                            ratio: (Math.max(fg, bg) + .05) / (Math.min(fg, bg) + .05)});
                    }
                    holder.remove();
                }
            }
            return results;
        }, theme);
        for (const result of results) {
            expect.soft(result.ratio, `${theme} ${result.surface} ${result.platform} ${result.small ? '16px' : '20px'}`).toBeGreaterThanOrEqual(3);
            expect(result.width).toBe(result.small ? '16px' : '20px');
        }
        expect(new Set(results.map(result => result.color)).size).toBeGreaterThanOrEqual(12);
    }
    await page.emulateMedia({forcedColors: 'active'});
    const forced = await page.evaluate(() => {
        document.body.dataset.theme = 'paper';
        const icon = HostPlatform.render({platform_icon: 'docker'});
        document.body.append(icon);
        const reference = document.createElement('span');
        reference.style.color = 'CanvasText';
        document.body.append(reference);
        return [getComputedStyle(icon).color, getComputedStyle(reference).color];
    });
    expect(forced[0]).toBe(forced[1]);
});
