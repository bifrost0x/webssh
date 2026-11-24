const { test, expect } = require('playwright/test');
const { login, assertNoExternalRequests } = require('./helpers');

async function freezeClock(page) {
    await page.clock.install();
    await page.clock.pauseAt(new Date());
}

test('error and warning toasts stay readable, pause on hover or focus and can be dismissed', async ({ page }) => {
    await login(page);
    await freezeClock(page);
    const toast = text => page.locator('#notificationContainer .notification').filter({ hasText: text });

    await page.evaluate(() => window.showNotification('Upload failed', 'error'));
    const error = toast('Upload failed');
    await expect(error).toHaveAttribute('role', 'alert');
    const dismiss = error.getByRole('button', { name: 'Dismiss notification', exact: true });
    await expect(dismiss).toHaveAttribute('type', 'button');
    await expect(dismiss.locator('.material-icons')).toHaveAttribute('aria-hidden', 'true');
    await page.clock.runFor(4000);
    await expect(error).toBeVisible();
    await page.clock.runFor(4500);
    await expect(error).toHaveCount(0);

    await page.evaluate(() => window.showNotification('Disk almost full', 'warning'));
    const warning = toast('Disk almost full');
    await warning.hover();
    await page.clock.runFor(30000);
    await expect(warning).toBeVisible();
    await page.mouse.move(1, 1);
    await page.clock.runFor(7000);
    await expect(warning).toBeVisible();
    await page.clock.runFor(1500);
    await expect(warning).toHaveCount(0);

    await page.evaluate(() => window.showNotification('Keyboard read', 'error'));
    const focused = toast('Keyboard read');
    await focused.getByRole('button', { name: 'Dismiss notification' }).focus();
    await page.clock.runFor(30000);
    await expect(focused).toBeVisible();
    await page.keyboard.press('Enter');
    await page.clock.runFor(400);
    await expect(focused).toHaveCount(0);

    await page.evaluate(() => window.showNotification('Saved', 'success'));
    const success = toast('Saved');
    await expect(success).toHaveAttribute('role', 'status');
    await expect(success.getByRole('button')).toHaveCount(0);
    await page.clock.runFor(2400);
    await expect(success).toHaveCount(0);

    await page.evaluate(() => window.showNotification('Short error', 'error', 1000));
    await page.clock.runFor(1400);
    await expect(toast('Short error')).toHaveCount(0);

    await page.evaluate(() => window.showNotification({ message: 'Stays put', type: 'info', persistent: true }));
    await page.clock.runFor(60000);
    await expect(toast('Stays put')).toBeVisible();
    await toast('Stays put').getByRole('button', { name: 'Dismiss notification' }).click();
    await page.clock.runFor(400);
    await expect(toast('Stays put')).toHaveCount(0);

    await page.evaluate(() => {
        i18n.setLanguage('de');
        window.showNotification('Fehler', 'error');
    });
    await expect(toast('Fehler').getByRole('button', { name: 'Benachrichtigung schließen', exact: true })).toBeVisible();
    await assertNoExternalRequests(page);
});

async function addDialog(page, id) {
    await page.evaluate(dialogId => {
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.id = dialogId;
        modal.setAttribute('role', 'dialog');
        modal.setAttribute('aria-modal', 'true');
        modal.setAttribute('aria-hidden', 'true');
        modal.innerHTML = `<div class="modal-content"><div class="modal-body">
            <input id="${dialogId}-first" aria-label="first">
            <button type="button" id="${dialogId}-middle">Middle</button>
            <input id="${dialogId}-last" aria-label="last">
            <button type="button" hidden>Hidden</button>
            <span hidden><button type="button">Inside hidden</button></span>
            <button type="button" style="display:none">Not displayed</button>
            <button type="button" tabindex="-1">Skipped</button>
            <button type="submit" id="${dialogId}-submit" disabled>Disabled submit</button>
        </div></div>`;
        document.body.appendChild(modal);
    }, id);
}

test('dialog focus trap skips disabled and hidden controls and survives stacked dialogs', async ({ page }) => {
    await login(page);
    await addDialog(page, 'trapLower');
    await addDialog(page, 'trapUpper');

    await page.evaluate(() => window.ModalManager.open(document.getElementById('trapLower')));
    await expect(page.locator('#trapLower-first')).toBeFocused();
    await page.locator('#trapLower-last').focus();
    await page.keyboard.press('Tab');
    await expect(page.locator('#trapLower-first')).toBeFocused();
    await page.keyboard.press('Shift+Tab');
    await expect(page.locator('#trapLower-last')).toBeFocused();

    await page.evaluate(() => window.ModalManager.open(document.getElementById('trapUpper')));
    await expect(page.locator('#trapUpper-first')).toBeFocused();
    await page.locator('#trapUpper-last').focus();
    await page.keyboard.press('Tab');
    await expect(page.locator('#trapUpper-first')).toBeFocused();

    await page.evaluate(() => window.ModalManager.close(document.getElementById('trapUpper')));
    expect(await page.evaluate(() => window.ModalManager.activeModal?.id)).toBe('trapLower');
    await page.locator('#trapLower-last').focus();
    await page.keyboard.press('Tab');
    await expect(page.locator('#trapLower-first')).toBeFocused();

    // Focus that fell back to the page re-enters the active dialog.
    await page.evaluate(() => document.activeElement.blur());
    await page.keyboard.press('Tab');
    await expect(page.locator('#trapLower-first')).toBeFocused();

    await page.evaluate(() => window.ModalManager.close(document.getElementById('trapLower')));
    expect(await page.evaluate(() => window.ModalManager.activeModal)).toBeNull();
    await assertNoExternalRequests(page);
});

test('the connection dialog keeps Tab inside while Connect is disabled', async ({ page }) => {
    await login(page);
    await page.evaluate(() => {
        window.ModalManager.open(document.getElementById('connectionModal'));
        document.getElementById('connectBtn').disabled = true;
    });
    const lastId = await page.evaluate(() => {
        const modal = document.getElementById('connectionModal');
        const controls = window.ModalManager.focusableElements(modal);
        const last = controls[controls.length - 1];
        last.id ||= 'trapProbeLast';
        return last.id;
    });
    expect(lastId).not.toBe('connectBtn');
    await page.locator(`[id="${lastId}"]`).focus();
    await page.keyboard.press('Tab');
    expect(await page.evaluate(() => document.getElementById('connectionModal').contains(document.activeElement))).toBe(true);
    await assertNoExternalRequests(page);
});
