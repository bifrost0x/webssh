/* Explicit recipient snapshots; new and reconnected sessions require a new selection. */
(function () {
    'use strict';
    const byId = id => document.getElementById(id);
    const t = (key, fallback) => window.i18n?.t(`terminalSafety.${key}`, fallback) || fallback;
    const guard = () => window.TerminalPasteGuard;
    const connectedSessions = () => typeof SessionManager === 'undefined' ? [] : SessionManager.getAllSessions().filter(s => s?.connected);
    let selection = [];
    let stale = false;
    let sending = false;
    const BroadcastInput = {
        open: false,
        toggle() { this.open ? this.close() : this.show(); },
        show() {
            this.open = true;
            document.body.classList.add('broadcast-active');
            byId('broadcastBar')?.classList.remove('hidden');
            byId('broadcastToggleBtn')?.classList.add('active');
            byId('broadcastToggleBtn')?.setAttribute('aria-pressed', 'true');
            this.updateCount();
            this.chooseRecipients();
        },
        close() {
            this.open = false;
            selection = selection.slice();
            guard()?.onWorkspaceChange();
            document.body.classList.remove('broadcast-active');
            byId('broadcastBar')?.classList.add('hidden');
            byId('broadcastToggleBtn')?.classList.remove('active');
            byId('broadcastToggleBtn')?.setAttribute('aria-pressed', 'false');
            byId('broadcastRecipientDialog')?.close();
        },
        selectRecipients(ids, candidates = connectedSessions().map(s => guard()?.capture(s.id, null, false))) {
            const requested = new Set(ids);
            const chosen = candidates.filter(binding => binding && requested.has(binding.id));
            if (chosen.length !== requested.size || chosen.some(binding => !guard()?.valid(binding))) return false;
            selection = chosen;
            stale = false;
            guard()?.onWorkspaceChange();
            this.updateCount();
            return true;
        },
        chooseRecipients() {
            if (sending) return;
            const dialog = byId('broadcastRecipientDialog');
            if (!dialog) return;
            const list = byId('broadcastRecipientList');
            list.replaceChildren();
            const candidates = connectedSessions().map(s => guard()?.capture(s.id, null, false)).filter(Boolean);
            for (const binding of candidates) {
                const row = document.createElement('label');
                row.className = 'terminal-recipient';
                const checkbox = document.createElement('input');
                checkbox.type = 'checkbox';
                checkbox.value = binding.id;
                checkbox.checked = !stale && selection.some(item => item.session === binding.session && guard().valid(item));
                const details = document.createElement('span');
                const endpoint = document.createElement('strong');
                endpoint.textContent = binding.endpoint;
                const context = document.createElement('small');
                context.textContent = [binding.session.displayName, binding.id].filter(Boolean).join(' · ');
                details.append(endpoint, context);
                row.append(checkbox, details);
                list.append(row);
            }
            if (!candidates.length) list.textContent = t('noRecipients', 'No connected sessions.');
            byId('broadcastRecipientError').textContent = '';
            byId('broadcastRecipientApply').onclick = () => {
                const ids = Array.from(list.querySelectorAll('input:checked'), input => input.value);
                if (!this.selectRecipients(ids, candidates)) {
                    byId('broadcastRecipientError').textContent = t('broadcastChanged', 'Recipients changed. Choose the connected sessions again before sending.');
                    return;
                }
                dialog.close();
                byId('broadcastInput')?.focus();
            };
            dialog.showModal();
        },
        updateCount() {
            if (selection.some(binding => !guard()?.valid(binding))) stale = true;
            if (byId('broadcastCount')) byId('broadcastCount').textContent = String(selection.length);
            if (byId('broadcastTargets')) byId('broadcastTargets').textContent = selection.map(binding => `${binding.endpoint} (${binding.id})`).join(', ');
            if (byId('broadcastSelectionStatus')) byId('broadcastSelectionStatus').textContent = stale
                ? t('broadcastChanged', 'Recipients changed. Choose the connected sessions again before sending.')
                : selection.length ? t('frozen', 'Only the selected sessions receive input. New sessions are not added.')
                    : t('chooseFirst', 'Choose recipients before sending.');
            if (byId('broadcastSendBtn')) byId('broadcastSendBtn').disabled = sending || stale || !selection.length;
            if (byId('broadcastSelectBtn')) byId('broadcastSelectBtn').disabled = sending;
        },
        async sendAll(text) {
            this.updateCount();
            if (sending || stale || !selection.length || !window.SSHInput) return 0;
            sending = true;
            this.updateCount();
            const recipients = selection;
            try {
                const isCurrent = () => selection === recipients && !stale;
                const result = await guard().review(recipients, text, async value => {
                    // Revalidate the entire frozen set immediately before the first send.
                    if (!isCurrent() || !recipients.every(binding => guard().valid(binding))) return 0;
                    const results = await Promise.allSettled(recipients.map(binding => (
                        guard().valid(binding) ? window.SSHInput.sendText(binding.id, value + '\r') : false
                    )));
                    return results.filter(item => item.status === 'fulfilled' && item.value === true).length;
                }, {isCurrent, titleKey: 'broadcastReviewTitle', warningKey: 'broadcastReviewWarning',
                    confirmKey: 'sendSelected', changedMessage: t('broadcastChanged')});
                return Number(result) || 0;
            } finally {
                sending = false;
                this.updateCount();
            }
        }
    };
    window.BroadcastInput = BroadcastInput;
    document.addEventListener('DOMContentLoaded', () => {
        const input = byId('broadcastInput');
        const submit = async () => {
            if (!input?.value || sending) return;
            const text = input.value;
            const expected = selection.length;
            const count = await BroadcastInput.sendAll(text);
            if (count > 0 && count === expected) {
                if (input.value === text) input.value = '';
                window.showNotification?.((window.i18n?.t('broadcast.sent') || 'Sent to {n} sessions').replace('{n}', count), 'info');
            } else {
                window.showNotification?.(count > 0
                    ? t('partial', 'Some recipients did not accept the input. Check each session before retrying; the command may already have run.')
                    : t('notSent', 'Input was not sent. Check the selected recipients and connection.'), 'warning');
            }
            input.focus();
        };
        byId('broadcastToggleBtn')?.addEventListener('click', () => BroadcastInput.toggle());
        byId('broadcastSelectBtn')?.addEventListener('click', () => BroadcastInput.chooseRecipients());
        byId('broadcastSendBtn')?.addEventListener('click', submit);
        byId('broadcastCloseBtn')?.addEventListener('click', () => BroadcastInput.close());
        byId('broadcastRecipientCancel')?.addEventListener('click', () => byId('broadcastRecipientDialog').close());
        byId('broadcastRecipientDialog')?.addEventListener('keydown', event => event.stopPropagation());
        input?.addEventListener('keydown', event => {
            if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) { event.preventDefault(); submit(); }
            else if (event.key === 'Escape') { event.preventDefault(); BroadcastInput.close(); }
        });
        window.addEventListener('session-workspace-change', () => BroadcastInput.updateCount());
        window.addEventListener('languageChanged', () => BroadcastInput.updateCount());
    });
}());
