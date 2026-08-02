const { test, expect } = require('playwright/test');
const { login } = require('./helpers');

test('login recovery remains reachable in a 720px-high viewport', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 720 });
    await page.goto('/login');
    const initialCardTop = await page.locator('.auth-card').evaluate(
        element => element.getBoundingClientRect().top
    );
    await page.locator('#recoveryLoginBtn').click();

    const submit = page.locator('#submitRecoveryLogin');
    await submit.scrollIntoViewIfNeeded();
    await expect(submit).toBeVisible();
    const layout = await page.evaluate(() => {
        const rect = document.querySelector('#submitRecoveryLogin').getBoundingClientRect();
        return {
            viewportHeight: window.innerHeight,
            bodyClientHeight: document.body.clientHeight,
            bodyScrollHeight: document.body.scrollHeight,
            submitTop: rect.top,
            submitBottom: rect.bottom,
            htmlOverflowY: getComputedStyle(document.documentElement).overflowY,
            bodyOverflowY: getComputedStyle(document.body).overflowY,
        };
    });

    expect(layout.bodyScrollHeight).toBeGreaterThan(layout.bodyClientHeight);
    expect(initialCardTop).toBeGreaterThanOrEqual(0);
    expect(layout.submitTop).toBeGreaterThanOrEqual(0);
    expect(layout.submitBottom).toBeLessThanOrEqual(layout.viewportHeight);
    expect(layout.htmlOverflowY).not.toBe('hidden');
    expect(layout.bodyOverflowY).not.toBe('hidden');
});

test('admin remains horizontally contained on a 390px viewport', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await login(page);
    await page.goto('/admin');

    const layout = await page.evaluate(() => {
        const main = document.querySelector('.admin-main').getBoundingClientRect();
        return {
            viewportWidth: window.innerWidth,
            documentWidth: document.documentElement.scrollWidth,
            bodyWidth: document.body.scrollWidth,
            mainLeft: main.left,
            mainRight: main.right,
        };
    });

    expect(layout.documentWidth).toBeLessThanOrEqual(layout.viewportWidth);
    expect(layout.bodyWidth).toBeLessThanOrEqual(layout.viewportWidth);
    expect(layout.mainLeft).toBeGreaterThanOrEqual(0);
    expect(layout.mainRight).toBeLessThanOrEqual(layout.viewportWidth);
});

test('admin audit logs remain mouse-scrollable in a short desktop viewport', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 320 });
    await login(page);
    await page.goto('/admin');
    await page.locator('.admin-tab[data-tab="audit"]').click();
    await expect(page.locator('#adminAuditBody tr')).not.toHaveCount(0);

    const main = page.locator('.admin-main');
    const layout = await main.evaluate(element => ({
        clientHeight: element.clientHeight,
        scrollHeight: element.scrollHeight,
        overflowY: getComputedStyle(element).overflowY,
    }));

    expect(layout.scrollHeight).toBeGreaterThan(layout.clientHeight);
    expect(['auto', 'scroll']).toContain(layout.overflowY);

    await main.hover();
    await page.mouse.wheel(0, 600);
    await expect.poll(() => main.evaluate(element => element.scrollTop)).toBeGreaterThan(0);
});

test('admin security actions and empty host trust use user-facing copy', async ({ page }) => {
    await login(page);
    await page.goto('/admin');

    await expect(page.locator('button[data-act="recovery"]').first()).toHaveText('Recovery');
    await page.locator('.admin-tab[data-tab="settings"]').click();
    await expect(page.locator('#globalHostKeyList')).toContainText(
        'No global host keys stored.'
    );
    await expect(page.locator('#globalHostKeyList td')).toHaveAttribute('colspan', '5');
});
