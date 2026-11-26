const {test, expect} = require('playwright/test');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');

async function load(page) {
    await page.setContent('<body class="webssh-ui webssh-shell" data-theme="glass"></body>');
    await page.addStyleTag({path: path.join(root, 'static/css/host-platform.css')});
    await page.addScriptTag({path: path.join(root, 'static/js/host-platform.js')});
}

test('a parent sizes service logos and monograms through --service-icon-size', async ({page}) => {
    await load(page);
    const sizes = await page.evaluate(() => {
        const plain = document.createElement('div');
        const sized = document.createElement('div');
        sized.style.setProperty('--service-icon-size', '20px');
        document.body.append(plain, sized);
        const measure = (holder, id) => {
            const icon = HostPlatform.renderService(id, document);
            icon.style.maskImage = icon.style.maskImage || '';
            holder.append(icon);
            const box = icon.getBoundingClientRect();
            return [box.width, box.height];
        };
        return {
            logoDefault: measure(plain, 'immich'), logoSized: measure(sized, 'immich'),
            monogramDefault: measure(plain, 'samba'), monogramSized: measure(sized, 'samba'),
        };
    });
    expect(sizes).toEqual({logoDefault: [16, 16], logoSized: [20, 20], monogramDefault: [16, 16], monogramSized: [20, 20]});
});

test('forced colours draw service logos in CanvasText despite a consumer tint', async ({page}) => {
    await page.emulateMedia({forcedColors: 'active'});
    await load(page);
    await page.addStyleTag({content: '[data-role] .host-service-icon { color: rgb(255, 0, 0); }'});
    const colors = await page.evaluate(() => {
        const tile = document.createElement('div');
        tile.dataset.role = 'web';
        document.body.append(tile);
        const icon = HostPlatform.renderService('samba', document);
        tile.append(icon);
        const probe = document.createElement('span');
        probe.style.color = 'CanvasText';
        probe.style.forcedColorAdjust = 'none';
        document.body.append(probe);
        return {icon: getComputedStyle(icon).color, canvasText: getComputedStyle(probe).color};
    });
    expect(colors.icon).toBe(colors.canvasText);
    expect(colors.icon).not.toBe('rgb(255, 0, 0)');
});
