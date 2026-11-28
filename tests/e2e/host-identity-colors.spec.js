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

test('role tiles, identity lines, app chips, virtualization labels and platform icons stay readable in the real components', async ({page}) => {
    const root = path.resolve(__dirname, '../..');
    const template = fs.readFileSync(path.join(root, 'templates/index.html'), 'utf8');
    const sheets = [...template.matchAll(/filename='(css\/[^']+\.css)'/g)].map(match => match[1]);
    await page.setContent('<body class="webssh-ui webssh-shell"></body>');
    for (const sheet of sheets) await page.addStyleTag({path: path.join(root, 'static', sheet)});
    await page.addScriptTag({path: path.join(root, 'static/js/host-platform.js')});
    await page.addScriptTag({path: path.join(root, 'static/js/host-identity.js')});
    for (const theme of THEMES) {
        const {results, expected} = await page.evaluate(theme => {
            document.body.dataset.theme = theme;
            const parse = value => {
                const numbers = value.match(/[\d.]+/g).map(Number);
                const srgb = value.startsWith('color(');
                const channels = numbers.slice(0, 3).map(v => (srgb ? v * 255 : v));
                const alpha = value.includes('/') || value.startsWith('rgba') ? numbers[3] : 1;
                return {channels, alpha: alpha ?? 1};
            };
            const over = (top, bottom) => top.channels.map((v, i) => v * top.alpha + bottom[i] * (1 - top.alpha));
            const luminance = channels => channels.map(v => v / 255)
                .map(v => (v <= .04045 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4))
                .reduce((sum, value, i) => sum + value * [.2126, .7152, .0722][i], 0);
            const ratio = (a, b) => {
                const [x, y] = [luminance(a), luminance(b)];
                return (Math.max(x, y) + .05) / (Math.min(x, y) + .05);
            };
            // Flattens the background colours behind the element's text, own background
            // included. Platform icons are masks painted with currentColor, so theirs is
            // the ink, not a background: start at the parent for those.
            const backdrop = (element, own = true) => {
                const layers = [];
                for (let node = own ? element : element.parentElement; node; node = node.parentElement) {
                    layers.push(parse(getComputedStyle(node).backgroundColor));
                }
                const base = parse(getComputedStyle(document.body).backgroundColor);
                let result = base.alpha ? base.channels : [255, 255, 255];
                for (const layer of layers.reverse()) if (layer.alpha) result = over(layer, result);
                return result;
            };
            const ink = element => parse(getComputedStyle(element).color).channels;
            const accentOf = element => {
                const swatch = document.createElement('span');
                swatch.style.color = 'var(--role)';
                element.append(swatch);
                const channels = parse(getComputedStyle(swatch).color).channels;
                swatch.remove();
                return channels;
            };
            const results = [];
            const mount = html => {
                const holder = document.createElement('div');
                holder.innerHTML = html;
                document.body.append(holder);
                return holder;
            };
            const platforms = Object.keys(HostPlatform.labels);
            for (const role of HostIdentity.ROLES) {
                const card = mount(`<div class="od-host" data-role="${role}"><div class="od-host-logo"></div><ul class="od-app-list"><li class="od-app"><span>Immich</span></li></ul></div>`);
                const icon = HostPlatform.render({platform_icon: 'debian'});
                card.querySelector('.od-host-logo').prepend(icon);
                results.push({what: `${role} platform icon on the role tile`, min: 3, value: ratio(ink(icon), backdrop(icon, false))});
                const chip = card.querySelector('.od-app');
                const logo = HostPlatform.renderService('immich');
                chip.prepend(logo);
                results.push({what: `${role} app logo on its chip`, min: 3, value: ratio(ink(logo), backdrop(logo, false))});
                results.push({what: `${role} app name on its chip`, min: 4.5, value: ratio(ink(chip.lastElementChild), backdrop(chip))});
                card.remove();

                // The identity line fades from 16% of the role colour on the left; test that end.
                const bar = mount(`<div class="session-identity-bar" data-role="${role}"><span class="session-identity-text"><span class="session-identity-role">x</span><span class="session-identity-name">y</span></span><span class="session-identity-apps">Paperless, nginx</span></div>`);
                const identity = bar.firstElementChild;
                const roleText = identity.querySelector('.session-identity-role');
                const apps = identity.querySelector('.session-identity-apps');
                const tinted = over({channels: accentOf(identity), alpha: .16}, backdrop(identity));
                results.push({what: `${role} identity role text`, min: 4.5, value: ratio(ink(roleText), tinted)});
                results.push({what: `${role} identity host name`, min: 4.5, value: ratio(ink(identity.querySelector('.session-identity-name')), tinted)});
                // The names sit at the right end, where the role tint has faded into the surface.
                results.push({what: `${role} identity service names`, min: 4.5, value: ratio(ink(apps), backdrop(identity))});
                results.push({what: `${role} identity service names on the tint`, min: 4.5, value: ratio(ink(apps), tinted)});
                bar.remove();
            }
            for (const platform of platforms) {
                const modern = mount('<div class="od-host"><div class="od-host-logo"></div><span class="od-host-system"><span class="od-host-os">Debian 12</span> · <span class="od-virt">KVM</span></span></div>');
                const icon = HostPlatform.render({platform_icon: platform});
                modern.querySelector('.od-host-logo').prepend(icon);
                results.push({what: `${platform} platform icon on the plain tile`, min: 3, value: ratio(ink(icon), backdrop(icon, false))});
                const virt = modern.querySelector('.od-virt');
                results.push({what: `${platform} card virtualization label`, min: 4.5, value: ratio(ink(virt), backdrop(virt))});
                modern.remove();
                const classic = mount('<div id="connectionOverview"><div class="overview-host-entry"><div class="overview-row"><span class="overview-row-virt">KVM</span></div></div></div>');
                const row = classic.querySelector('.overview-row');
                const classicIcon = HostPlatform.render({platform_icon: platform});
                row.prepend(classicIcon);
                results.push({what: `${platform} classic platform icon`, min: 3, value: ratio(ink(classicIcon), backdrop(classicIcon, false))});
                const badge = row.querySelector('.overview-row-virt');
                results.push({what: `${platform} classic virtualization badge`, min: 4.5, value: ratio(ink(badge), backdrop(badge))});
                classic.remove();
            }
            return {results, expected: HostIdentity.ROLES.length * 7 + platforms.length * 4};
        }, theme);
        expect(results).toHaveLength(expected);
        for (const result of results) expect.soft(result.value, `${theme} ${result.what}`).toBeGreaterThanOrEqual(result.min);
        if (process.env.CONTRAST_REPORT) {
            const mins = {};
            for (const r of results) {
                const key = r.what.replace(/^\S+ /, '').replace(/^(platform icon on the plain tile|card virtualization label|classic platform icon|classic virtualization badge) ?/, '$1');
                mins[key] = Math.min(mins[key] ?? 99, r.value);
            }
            console.log(`MINS ${theme} ${JSON.stringify(Object.fromEntries(Object.entries(mins).map(([k, v]) => [k, +v.toFixed(2)])))}`);
        }
    }
});
