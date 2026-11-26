const {test, expect} = require('playwright/test');
const fs = require('node:fs');
const path = require('node:path');

const THEMES = ['glass', 'werkbank', 'retro', 'solar', 'paper', 'noir', 'arctic-ice', 'rose-gold', 'cyberpunk-neon', 'emerald-matrix', 'obsidian'];

test('every role keeps its accent and pill text readable on every theme surface', async ({page}) => {
    const root = path.resolve(__dirname, '../..');
    const template = fs.readFileSync(path.join(root, 'templates/index.html'), 'utf8');
    const sheets = [...template.matchAll(/filename='(css\/[^']+\.css)'/g)].map(match => match[1]);
    expect(sheets).toContain('css/host-identity.css');
    await page.setContent('<body class="webssh-ui webssh-shell"></body>');
    for (const sheet of sheets) await page.addStyleTag({path: path.join(root, 'static', sheet)});
    await page.addScriptTag({path: path.join(root, 'static/js/host-platform.js')});
    await page.addScriptTag({path: path.join(root, 'static/js/host-identity.js')});
    for (const theme of THEMES) {
        const results = await page.evaluate(theme => {
            document.body.dataset.theme = theme;
            // Computed colours come back as rgb()/rgba() (0-255) or color(srgb ...) (0-1).
            const parse = value => {
                const numbers = value.match(/[\d.]+/g).map(Number);
                const srgb = value.startsWith('color(');
                const channels = numbers.slice(0, 3).map(v => (srgb ? v * 255 : v));
                const alpha = value.includes('/') || value.startsWith('rgba') ? numbers[3] : 1;
                return {channels, alpha: alpha ?? 1};
            };
            const over = (top, bottom) => top.channels.map((v, i) => v * top.alpha + bottom.channels[i] * (1 - top.alpha));
            const luminance = channels => channels.map(v => v / 255)
                .map(v => (v <= .04045 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4))
                .reduce((sum, value, i) => sum + value * [.2126, .7152, .0722][i], 0);
            const ratio = (a, b) => {
                const [x, y] = [luminance(a), luminance(b)];
                return (Math.max(x, y) + .05) / (Math.min(x, y) + .05);
            };
            const results = [];
            for (const surface of ['canvas', 'surface', 'panel', 'raised', 'row-hover']) {
                const holder = document.createElement('div');
                holder.style.backgroundColor = `var(--ws2-${surface})`;
                document.body.append(holder);
                const background = parse(getComputedStyle(holder).backgroundColor).channels;
                for (const role of HostIdentity.ROLES) {
                    const accent = document.createElement('span');
                    accent.dataset.role = role;
                    accent.style.color = 'var(--role)';
                    accent.textContent = HostIdentity.ROLE_GLYPHS[role];
                    const pill = document.createElement('span');
                    pill.className = 'host-role-pill';
                    pill.dataset.role = role;
                    pill.textContent = role;
                    holder.append(accent, pill);
                    const style = getComputedStyle(pill);
                    const pillBackground = over(parse(style.backgroundColor), {channels: background});
                    results.push({
                        role, surface,
                        accentColor: getComputedStyle(accent).color,
                        accent: ratio(parse(getComputedStyle(accent).color).channels, background),
                        pill: ratio(parse(style.color).channels, pillBackground),
                    });
                }
                holder.remove();
            }
            return results;
        }, theme);
        expect(results).toHaveLength(17 * 5);
        for (const result of results) {
            expect.soft(result.accent, `${theme} ${result.surface} ${result.role} accent`).toBeGreaterThanOrEqual(3);
            expect.soft(result.pill, `${theme} ${result.surface} ${result.role} pill text`).toBeGreaterThanOrEqual(4.5);
        }
        // Each role has its own colour in every theme.
        expect(new Set(results.map(result => result.accentColor)).size).toBe(17);
    }
    await page.emulateMedia({forcedColors: 'active'});
    // Forced colours repaint text on their own; the custom properties prove the
    // block exists, so tiles and borders built from --role follow the system too.
    const forced = await page.evaluate(() => HostIdentity.ROLES.map(role => {
        document.body.dataset.theme = 'paper';
        const element = document.createElement('span');
        element.dataset.role = role;
        document.body.append(element);
        const style = getComputedStyle(element);
        const values = [style.getPropertyValue('--role').trim(), style.getPropertyValue('--role-ink').trim()];
        element.remove();
        return {role, values};
    }));
    for (const {role, values} of forced) expect(values, role).toEqual(['CanvasText', 'CanvasText']);
});
