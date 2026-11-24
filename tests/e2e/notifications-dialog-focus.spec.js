const { test, expect } = require('playwright/test');
const { login, assertNoExternalRequests } = require('./helpers');

async function freezeClock(page) {
    await page.clock.install();
    await page.clock.pauseAt(new Date());
}

test('repeated failures keep only a few timed toasts on screen', async ({ page }) => {
    await login(page);
    await freezeClock(page);
    const toasts = page.locator('#notificationContainer .notification:not(.fade-out)');
    await page.evaluate(() => {
        window.showNotification({ message: 'Keep me', type: 'info', persistent: true });
        for (let index = 1; index <= 7; index += 1) window.showNotification(`Reconnect failed ${index}`, 'error');
    });
    await expect(toasts.filter({ hasText: 'Reconnect failed' })).toHaveCount(4);
    await expect(toasts.filter({ hasText: 'Reconnect failed 7' })).toBeVisible();
    await expect(toasts.filter({ hasText: 'Reconnect failed 1' })).toHaveCount(0);
    await expect(toasts.filter({ hasText: 'Keep me' })).toBeVisible();
});

test('success toasts never push unread errors off screen', async ({ page }) => {
    await login(page);
    await freezeClock(page);
    const toasts = page.locator('#notificationContainer .notification:not(.fade-out)');
    await page.evaluate(() => {
        window.showNotification('Saved 1', 'success');
        for (let index = 1; index <= 3; index += 1) window.showNotification(`Upload failed ${index}`, 'error');
        window.showNotification('Saved 2', 'success');
        window.showNotification('Saved 3', 'info');
    });
    await expect(toasts).toHaveCount(4);
    for (let index = 1; index <= 3; index += 1) {
        await expect(toasts.filter({ hasText: `Upload failed ${index}` })).toBeVisible();
    }
    await expect(toasts.filter({ hasText: 'Saved 1' })).toHaveCount(0);
    await expect(toasts.filter({ hasText: 'Saved 2' })).toHaveCount(0);
    await expect(toasts.filter({ hasText: 'Saved 3' })).toBeVisible();

    // A fourth error still fits once the success toast gives way.
    await page.evaluate(() => window.showNotification('Upload failed 4', 'warning'));
    await expect(toasts).toHaveCount(4);
    await expect(toasts.filter({ hasText: 'Saved 3' })).toHaveCount(0);
    await expect(toasts.filter({ hasText: 'Upload failed 1' })).toBeVisible();
    // With only errors left, a success is not shown at all.
    await page.evaluate(() => window.showNotification('Saved 4', 'success'));
    await expect(toasts.filter({ hasText: 'Saved 4' })).toHaveCount(0);
    await expect(toasts).toHaveCount(4);
});

test('phones keep at most two timed toasts', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await login(page);
    await freezeClock(page);
    const toasts = page.locator('#notificationContainer .notification:not(.fade-out)');
    await page.evaluate(() => {
        window.showNotification('First error', 'error');
        window.showNotification('Copied', 'success');
        window.showNotification('Second error', 'error');
        window.showNotification('Third error', 'error');
    });
    await expect(toasts).toHaveCount(2);
    await expect(toasts.filter({ hasText: 'Second error' })).toBeVisible();
    await expect(toasts.filter({ hasText: 'Third error' })).toBeVisible();
});

test('closing a toast from the keyboard keeps focus in place and Escape closes it', async ({ page }) => {
    await login(page);
    await freezeClock(page);
    const trigger = page.locator('#notificationTrigger');
    await page.evaluate(() => {
        const button = document.createElement('button');
        button.id = 'notificationTrigger';
        button.type = 'button';
        button.textContent = 'Trigger';
        document.body.appendChild(button);
        button.focus();
        window.showNotification('Error one', 'error');
        window.showNotification('Error two', 'error');
    });
    const toast = text => page.locator('#notificationContainer .notification:not(.fade-out)').filter({ hasText: text });
    const closeOne = toast('Error one').getByRole('button', { name: 'Dismiss notification' });
    await trigger.focus();
    await closeOne.focus();
    await page.keyboard.press('Enter');
    await expect(toast('Error two').getByRole('button', { name: 'Dismiss notification' })).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(toast('Error two')).toHaveCount(0);
    await expect(trigger).toBeFocused();
    expect(await page.evaluate(() => document.activeElement?.tagName)).not.toBe('BODY');
});

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

    await page.evaluate(async () => {
        await i18n.setLanguage('de');
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

    // Some dialogs are shown again without open() and keep a stale root aria-hidden.
    await page.evaluate(() => {
        const modal = document.getElementById('trapLower');
        modal.classList.add('show');
        window.ModalManager.activeModal = modal;
    });
    await expect(page.locator('#trapLower')).toHaveAttribute('aria-hidden', 'true');
    await page.locator('#trapLower-last').focus();
    await page.keyboard.press('Tab');
    await expect(page.locator('#trapLower-first')).toBeFocused();
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
