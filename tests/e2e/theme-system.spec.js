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
    await page.getByRole('link', { name: 'Settings' }).click();
    await expect(page).toHaveURL(/\/settings#preferences$/);
    await expect(page.getByRole('heading', { name: 'Preferences' })).toBeVisible();
    await page.evaluate(() => document.fonts.ready);
}

async function selectTheme(page, selector, themeId) {
    await selector.selectOption(themeId);
    await expect(page.locator('#settingsPreferenceStatus')).toHaveText('Theme saved.');
    await expect(selector).toBeEnabled();
    await expect(page.locator('body')).toHaveAttribute('data-theme', themeId);
    await expect.poll(() => page.evaluate(() => localStorage.getItem('websshTheme')))
        .toBe(themeId);
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
                workspace: rect('.admin-navigation'),
                notepad: rect('.admin-content'),
            },
            background: {
                image: backgroundStyle.backgroundImage,
                opacity: Number(backgroundStyle.opacity),
                pointerEvents: backgroundStyle.pointerEvents,
                size: backgroundStyle.backgroundSize,
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
                settingsLabel: getComputedStyle(
                    document.querySelector('.admin-settings-row label'),
                ).color,
                primaryText: rgb(bodyStyle.getPropertyValue('--text-primary').trim()),
                settingsLabelContrast: contrast(
                    getComputedStyle(
                        document.querySelector('.admin-settings-row label'),
                    ).color,
                    bodyStyle.getPropertyValue('--bg-secondary').trim(),
                ),
            },
        };
    });
}

async function readPaperAuthState(page) {
    return page.evaluate(() => {
        const rgb = value => value.match(/[\d.]+/g).map(Number).slice(0, 3);
        const luminance = value => {
            const channels = rgb(value).map(channel => {
                const normalized = channel / 255;
                return normalized <= 0.04045
                    ? normalized / 12.92
                    : ((normalized + 0.055) / 1.055) ** 2.4;
            });
            return (0.2126 * channels[0])
                + (0.7152 * channels[1])
                + (0.0722 * channels[2]);
        };
        const contrast = (foreground, background) => {
            const foregroundLuminance = luminance(foreground);
            const backgroundLuminance = luminance(background);
            return (Math.max(foregroundLuminance, backgroundLuminance) + 0.05)
                / (Math.min(foregroundLuminance, backgroundLuminance) + 0.05);
        };
        const darkContextSurface = 'rgb(7, 12, 21)';
        const contrastFor = selector => contrast(
            getComputedStyle(document.querySelector(selector)).color,
            darkContextSurface,
        );

        return {
            bodyBackground: getComputedStyle(document.body).backgroundColor,
            titleContrast: contrastFor('.auth-context-copy h1'),
            itemContrast: contrastFor('.auth-context-panel :is(.auth-product-pillars, .auth-path-list) strong'),
            footerContrast: contrastFor('.auth-context-footer'),
        };
    });
}

function expectStableGeometry(actual, expected) {
    for (const region of Object.keys(expected)) {
        for (const dimension of Object.keys(expected[region])) {
            expect(
                actual[region][dimension],
                `${region}.${dimension} should remain stable across themes`,
            ).toBeCloseTo(expected[region][dimension], 0);
        }
    }
}

test('all themes share one typography system without moving the Settings Center', async ({ page }) => {
    await login(page);
    await openThemeSettings(page);
    const baseline = await readThemeState(page);

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
        await selectTheme(page, selector, themeId);
        const state = await readThemeState(page);
        expect(state.fontFamily).toBe(baseline.fontFamily);
        expectStableGeometry(state.geometry, baseline.geometry);
    }
});

test('Paper Ops uses a tinted Blueprint Steel canvas instead of white surfaces', async ({ page }) => {
    await login(page);
    await openThemeSettings(page);
    await selectTheme(
        page,
        page.getByRole('combobox', { name: 'Theme' }),
        'paper',
    );

    const state = await readThemeState(page);
    expect(state.colors.secondaryLuminance).toBeLessThan(0.9);
    expect(state.colors.secondaryBlueBias).toBeGreaterThanOrEqual(8);
    expect(state.background.opacity).toBeGreaterThanOrEqual(0.17);
    expect(state.colors.mutedContrast).toBeGreaterThanOrEqual(4.5);
    expect(state.colors.settingsLabelContrast).toBeGreaterThanOrEqual(4.5);
    expect(state.colors.settingsLabel.match(/[\d.]+/g).map(Number).slice(0, 3))
        .toEqual(state.colors.primaryText);
});

test('professional themes use restrained local backgrounds', async ({ page }) => {
    await login(page);
    await openThemeSettings(page);
    const selector = page.getByRole('combobox', { name: 'Theme' });

    for (const [themeId, assetName] of Object.entries(PROFESSIONAL_THEME_BACKGROUNDS)) {
        await selectTheme(page, selector, themeId);
        const state = await readThemeState(page);
        expect(state.background.image).toContain(assetName);
        expect(state.background.opacity).toBeGreaterThanOrEqual(0.04);
        expect(state.background.opacity).toBeLessThanOrEqual(themeId === 'paper' ? 0.18 : 0.1);
        expect(state.background.pointerEvents).toBe('none');
        expect(state.background.size).toBe('cover');
    }

    await assertNoExternalRequests(page);
});

test('the last selected theme styles the next login screen', async ({ page }) => {
    await login(page);
    await openThemeSettings(page);
    await selectTheme(
        page,
        page.getByRole('combobox', { name: 'Theme' }),
        'paper',
    );
    await page.getByRole('link', { name: 'Back to Terminal' }).click();
    const logoutStatus = await page.evaluate(async () => {
        const csrf = document.querySelector('meta[name="csrf-token"]').content;
        const response = await fetch('/logout', {
            method: 'POST',
            headers: { 'X-CSRFToken': csrf },
        });
        return response.status;
    });
    expect(logoutStatus).toBe(200);
    await page.goto('/login');
    await expect(page).toHaveURL(/\/login/);
    await expect(page.locator('body')).toHaveAttribute('data-theme', 'paper');

    const authTheme = await page.evaluate(() => ({
        backdropImage: getComputedStyle(document.body, '::before').backgroundImage,
        cardImage: getComputedStyle(document.querySelector('.auth-card')).backgroundImage,
    }));
    expect(authTheme.backdropImage).toContain('paper-blueprint.png');
    expect(authTheme.cardImage).toContain('paper-blueprint.png');

    for (const path of ['/login', '/register']) {
        await page.goto(path);
        await expect(page.locator('body')).toHaveAttribute('data-theme', 'paper');
        const authState = await readPaperAuthState(page);
        expect(authState.bodyBackground).toBe('rgb(220, 229, 238)');
        expect(authState.titleContrast).toBeGreaterThanOrEqual(7);
        expect(authState.itemContrast).toBeGreaterThanOrEqual(7);
        expect(authState.footerContrast).toBeGreaterThanOrEqual(4.5);
    }

    await page.goto('/login');
    await page.getByRole('textbox', { name: 'Username' }).fill('e2e_mixed_mfa');
    await page.locator('#password').fill('browser-password');
    await page.getByRole('button', { name: 'Sign In' }).click();
    await expect(page.getByRole('button', { name: 'Back to sign in' })).toBeVisible();
    const mfaState = await readPaperAuthState(page);
    expect(mfaState.bodyBackground).toBe('rgb(220, 229, 238)');
    expect(mfaState.titleContrast).toBeGreaterThanOrEqual(7);
    expect(mfaState.itemContrast).toBeGreaterThanOrEqual(7);
    expect(mfaState.footerContrast).toBeGreaterThanOrEqual(4.5);
});

test('fun themes use local decorative backgrounds that cannot intercept input', async ({ page }) => {
    await login(page);
    await openThemeSettings(page);
    const selector = page.getByRole('combobox', { name: 'Theme' });

    for (const [themeId, assetName] of Object.entries(FUN_THEME_BACKGROUNDS)) {
        await selectTheme(page, selector, themeId);
        const state = await readThemeState(page);
        expect(state.background.image).toContain(assetName);
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
        await selectTheme(page, selector, themeId);
        const state = await readThemeState(page);
        expect(state.colors.mutedContrast).toBeGreaterThanOrEqual(4.5);
        if (themeId === 'emerald-matrix') {
            expect(state.colors.success).not.toBe(state.colors.accent);
        }
    }
});
