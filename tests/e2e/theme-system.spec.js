const { test, expect } = require('playwright/test');
const { assertNoExternalRequests, login } = require('./helpers');

const THEME_IDS = [
    'glass',
    'solar',
    'paper',
    'noir',
    'arctic-ice',
    'rose-gold',
    'obsidian',
    'retro',
    'cyberpunk-neon',
    'emerald-matrix',
];

const PROFESSIONAL_THEME_BACKGROUNDS = {
    glass: 'carbon-glass.png',
    solar: 'navy-topography.png',
    paper: 'paper-blueprint.png',
    noir: 'noir-architecture.png',
    'arctic-ice': 'arctic-frost.png',
    'rose-gold': 'rose-brushed-metal.png',
    obsidian: 'obsidian-glass.png',
};

const FUN_THEME_BACKGROUNDS = {
    retro: 'retro-amber.png',
    'cyberpunk-neon': 'neon-circuit.png',
    'emerald-matrix': 'matrix-signal.png',
};

async function openThemeSettings(page) {
    await page.getByRole('button', { name: 'Account menu' }).click();
    await page.getByRole('button', { name: 'Settings' }).click();
    await expect(page.getByRole('dialog', { name: 'Settings' })).toBeVisible();
}

async function readThemeState(page) {
    return page.evaluate(() => {
        const bodyStyle = getComputedStyle(document.body);
        const backgroundStyle = getComputedStyle(document.body, '::before');
        const rect = selector => {
            const bounds = document.querySelector(selector).getBoundingClientRect();
            return {
                x: bounds.x,
                y: bounds.y,
                width: bounds.width,
                height: bounds.height,
            };
        };
        const rgb = value => {
            const probe = document.createElement('span');
            probe.style.color = value;
            document.body.appendChild(probe);
            const match = getComputedStyle(probe).color.match(/[\d.]+/g).map(Number);
            probe.remove();
            return match.slice(0, 3);
        };
        const luminance = value => {
            const channels = rgb(value).map(channel => {
                const normalized = channel / 255;
                return normalized <= 0.04045
                    ? normalized / 12.92
                    : ((normalized + 0.055) / 1.055) ** 2.4;
            });
            return (0.2126 * channels[0]) + (0.7152 * channels[1]) + (0.0722 * channels[2]);
        };
        const contrast = (foreground, background) => {
            const foregroundLuminance = luminance(foreground);
            const backgroundLuminance = luminance(background);
            return (Math.max(foregroundLuminance, backgroundLuminance) + 0.05)
                / (Math.min(foregroundLuminance, backgroundLuminance) + 0.05);
        };

        return {
            theme: document.body.dataset.theme,
            fontFamily: bodyStyle.fontFamily,
            geometry: {
                header: rect('.header'),
                workspace: rect('.workspace'),
                notepad: rect('.notepad-panel'),
            },
            background: {
                image: backgroundStyle.backgroundImage,
                opacity: Number(backgroundStyle.opacity),
                pointerEvents: backgroundStyle.pointerEvents,
                size: backgroundStyle.backgroundSize,
                panelImage: getComputedStyle(document.querySelector('.terminal-pane')).backgroundImage,
                panelBlendMode: getComputedStyle(document.querySelector('.terminal-pane')).backgroundBlendMode,
                modalImage: getComputedStyle(document.querySelector('.modal-content')).backgroundImage,
                accountMenuImage: getComputedStyle(
                    document.querySelector('.account-dropdown-header'),
                ).backgroundImage,
                notepadImage: getComputedStyle(document.querySelector('.notepad-panel')).backgroundImage,
            },
            colors: {
                accent: bodyStyle.getPropertyValue('--accent-primary').trim(),
                success: bodyStyle.getPropertyValue('--success-color').trim(),
                secondaryLuminance: luminance(
                    bodyStyle.getPropertyValue('--bg-secondary').trim(),
                ),
                secondaryBlueBias: (() => {
                    const [red, , blue] = rgb(
                        bodyStyle.getPropertyValue('--bg-secondary').trim(),
                    );
                    return blue - red;
                })(),
                mutedContrast: contrast(
                    bodyStyle.getPropertyValue('--text-muted').trim(),
                    bodyStyle.getPropertyValue('--bg-secondary').trim(),
                ),
            },
        };
    });
}

function expectStableGeometry(actual, expected) {
    for (const region of Object.keys(expected)) {
        for (const dimension of Object.keys(expected[region])) {
            expect(actual[region][dimension]).toBeCloseTo(expected[region][dimension], 0);
        }
    }
}

test('all themes share one typography system without moving the workspace', async ({ page }) => {
    await login(page);
    const baseline = await readThemeState(page);
    await openThemeSettings(page);

    const selector = page.getByRole('combobox', { name: 'Theme' });
    await expect(selector.locator('option')).toHaveCount(10);
    expect(await selector.locator('option').evaluateAll(options => (
        options.map(option => option.value)
    ))).toEqual(THEME_IDS);
    expect(await selector.locator('optgroup').evaluateAll(groups => (
        groups.map(group => ({
            label: group.label,
            themes: [...group.querySelectorAll('option')].map(option => option.value),
        }))
    ))).toEqual([
        {
            label: 'Professional Themes',
            themes: Object.keys(PROFESSIONAL_THEME_BACKGROUNDS),
        },
        {
            label: 'Fun Themes',
            themes: Object.keys(FUN_THEME_BACKGROUNDS),
        },
    ]);

    for (const themeId of THEME_IDS) {
        await selector.selectOption(themeId);
        await expect(page.locator('body')).toHaveAttribute('data-theme', themeId);
        const state = await readThemeState(page);
        expect(state.fontFamily).toBe(baseline.fontFamily);
        expectStableGeometry(state.geometry, baseline.geometry);
    }
});

test('Paper Ops uses a tinted Blueprint Steel canvas instead of white surfaces', async ({ page }) => {
    await login(page);
    await openThemeSettings(page);
    await page.getByRole('combobox', { name: 'Theme' }).selectOption('paper');

    const state = await readThemeState(page);
    expect(state.colors.secondaryLuminance).toBeLessThan(0.9);
    expect(state.colors.secondaryBlueBias).toBeGreaterThanOrEqual(8);
    expect(state.background.opacity).toBeGreaterThanOrEqual(0.17);
    expect(state.colors.mutedContrast).toBeGreaterThanOrEqual(4.5);
});

test('professional themes use restrained local backgrounds', async ({ page }) => {
    await login(page);
    await openThemeSettings(page);
    const selector = page.getByRole('combobox', { name: 'Theme' });

    for (const [themeId, assetName] of Object.entries(PROFESSIONAL_THEME_BACKGROUNDS)) {
        await selector.selectOption(themeId);
        const state = await readThemeState(page);
        expect(state.background.image).toContain(assetName);
        expect(state.background.panelImage).toContain(assetName);
        expect(state.background.modalImage).toContain(assetName);
        expect(state.background.accountMenuImage).toContain(assetName);
        expect(state.background.notepadImage).toContain(assetName);
        expect(state.background.opacity).toBeGreaterThanOrEqual(0.04);
        expect(state.background.opacity).toBeLessThanOrEqual(themeId === 'paper' ? 0.18 : 0.1);
        expect(state.background.pointerEvents).toBe('none');
        expect(state.background.size).toBe('cover');
        expect(state.background.panelBlendMode).toBe(themeId === 'paper' ? 'normal' : 'soft-light');
    }

    await assertNoExternalRequests(page);
});

test('the last selected theme styles the next login screen', async ({ page }) => {
    await login(page);
    await openThemeSettings(page);
    await page.getByRole('combobox', { name: 'Theme' }).selectOption('paper');
    await expect.poll(() => page.evaluate(() => localStorage.getItem('websshTheme')))
        .toBe('paper');
    await page.getByRole('button', { name: 'Close', exact: true }).click();
    await page.getByRole('button', { name: 'Account menu' }).click();
    page.once('dialog', dialog => dialog.accept());
    await page.getByRole('button', { name: 'Logout' }).click();
    await expect(page).toHaveURL(/\/login/);
    await expect(page.locator('body')).toHaveAttribute('data-theme', 'paper');

    const authTheme = await page.evaluate(() => ({
        backdropImage: getComputedStyle(document.body, '::before').backgroundImage,
        cardImage: getComputedStyle(document.querySelector('.auth-card')).backgroundImage,
    }));
    expect(authTheme.backdropImage).toContain('paper-blueprint.png');
    expect(authTheme.cardImage).toContain('paper-blueprint.png');
});

test('fun themes use local decorative backgrounds that cannot intercept input', async ({ page }) => {
    await login(page);
    await openThemeSettings(page);
    const selector = page.getByRole('combobox', { name: 'Theme' });

    for (const [themeId, assetName] of Object.entries(FUN_THEME_BACKGROUNDS)) {
        await selector.selectOption(themeId);
        const state = await readThemeState(page);
        expect(state.background.image).toContain(assetName);
        expect(state.background.panelImage).toContain(assetName);
        expect(state.background.modalImage).toContain(assetName);
        expect(state.background.accountMenuImage).toContain(assetName);
        expect(state.background.notepadImage).toContain(assetName);
        expect(state.background.opacity).toBeGreaterThanOrEqual(0.08);
        expect(state.background.opacity).toBeLessThanOrEqual(0.22);
        expect(state.background.pointerEvents).toBe('none');
        expect(state.background.size).toBe('cover');
    }

    await assertNoExternalRequests(page);
});

test('muted copy stays readable and Matrix keeps success distinct from its identity color', async ({ page }) => {
    await login(page);
    await openThemeSettings(page);
    const selector = page.getByRole('combobox', { name: 'Theme' });

    for (const themeId of THEME_IDS) {
        await selector.selectOption(themeId);
        const state = await readThemeState(page);
        expect(state.colors.mutedContrast).toBeGreaterThanOrEqual(4.5);
        if (themeId === 'emerald-matrix') {
            expect(state.colors.success).not.toBe(state.colors.accent);
        }
    }
});
