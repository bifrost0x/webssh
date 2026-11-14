/* Session-bound paste review. Native clipboard events are intercepted before xterm. */
(function (root) {
    'use strict';
    const originalPastes = new WeakMap();
    let observedSocket = null;
    let transportRevision = 0;
    let activeRevision = 0;
    let previousActive = null;
    let pending = null;
    const byId = id => document.getElementById(id);
    const t = (key, fallback) => root.i18n?.t(`terminalSafety.${key}`, fallback) || fallback;
    const manager = () => typeof SessionManager !== 'undefined' ? SessionManager : null;
    const label = session => `${session.username || '?'}@${session.host || '?'}:${session.port || 22}`;
    const needsReview = text => /[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/.test(text);
    const trimTrailingNewlines = text => text.replace(/[\r\n]+$/, '');
    function visibleText(text) {
        return text.replace(/[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, char => {
            const names = {'\r': 'CR', '\n': 'LF', '\t': 'TAB', '\x1b': 'ESC', '\x7f': 'DEL'};
            return `[${names[char] || `U+${char.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')}`}]${char === '\n' || char === '\r' ? '\n' : ''}`;
        });
    }
    function notifyChanged(message) { root.showNotification?.(message || t('changed', 'Session changed. Nothing was pasted; try again in the intended session.'), 'warning'); }
    function cancel(changed = false) {
        const request = pending;
        pending = null;
        if (!request) return;
        byId('terminalPasteDialog')?.close();
        byId('terminalPastePreview').textContent = '';
        request.resolve(false);
        if (changed) notifyChanged(request.changedMessage);
    }
    function disconnected() {
        transportRevision += 1;
        cancel(true);
        root.BroadcastInput?.updateCount();
    }
    function observeSocket() {
        if (observedSocket === root.socket) return;
        observedSocket?.off?.('disconnect', disconnected);
        observedSocket = root.socket;
        transportRevision += 1;
        observedSocket?.on?.('disconnect', disconnected);
    }
    function syncActive() {
        const active = manager()?.getActiveSession?.() || null;
        if (previousActive !== active) {
            previousActive = active;
            activeRevision += 1;
        }
    }
    function capture(sessionId, terminal = null, requireActive = true) {
        observeSocket();
        syncActive();
        const session = manager()?.getSession(sessionId);
        if (!session?.connected || root.socket?.connected !== true) return null;
        if (requireActive && previousActive !== sessionId) return null;
        return {id: sessionId, session, terminal, endpoint: label(session),
            generation: session.inputGeneration || 0, socket: root.socket, socketId: root.socket.id,
            transportRevision, activeRevision: requireActive ? activeRevision : null};
    }
    function valid(binding) {
        observeSocket();
        syncActive();
        return Boolean(binding && manager()?.getSession(binding.id) === binding.session
            && binding.session.connected && label(binding.session) === binding.endpoint
            && (binding.session.inputGeneration || 0) === binding.generation
            && root.socket === binding.socket && root.socket?.connected === true
            && root.socket.id === binding.socketId && transportRevision === binding.transportRevision
            && (!binding.terminal || typeof TerminalManager === 'undefined'
                || Object.values(TerminalManager.terminals).includes(binding.terminal))
            && (binding.activeRevision === null || (previousActive === binding.id && activeRevision === binding.activeRevision)));
    }
    function onWorkspaceChange() {
        syncActive();
        if (pending && !pending.isCurrent()) cancel(true);
    }
    function review(binding, text, send, options = {}) {
        if (typeof text !== 'string' || !text) return Promise.resolve(false);
        const bindings = Array.isArray(binding) ? binding.slice() : [binding];
        const isCurrent = () => bindings.length > 0 && bindings.every(valid)
            && (!options.isCurrent || options.isCurrent());
        if (!isCurrent()) { notifyChanged(options.changedMessage); return Promise.resolve(false); }
        cancel();
        if (!isCurrent()) { notifyChanged(options.changedMessage); return Promise.resolve(false); }
        if (!needsReview(text)) return Promise.resolve(send(text));
        const dialog = byId('terminalPasteDialog');
        if (!dialog) return Promise.resolve(false);
        byId('terminalPasteTarget').textContent = bindings.map(target => `${target.endpoint} · ${target.id}`).join('\n');
        for (const [id, key] of [['terminalPasteTitle', options.titleKey || 'pasteTitle'],
            ['terminalPasteWarning', options.warningKey || 'pasteWarning'],
            ['terminalPasteConfirm', options.confirmKey || 'pasteConfirm']]) {
            const element = byId(id);
            element.dataset.i18n = `terminalSafety.${key}`;
            element.textContent = t(key);
        }
        const trim = byId('terminalPasteTrim');
        trim.checked = false;
        trim.disabled = trimTrailingNewlines(text) === text;
        byId('terminalPastePreview').textContent = visibleText(text);
        return new Promise(resolve => {
            pending = {isCurrent, changedMessage: options.changedMessage, text, send, resolve};
            dialog.showModal();
            byId('terminalPasteCancel').focus();
        });
    }
    function paste(binding, text) {
        return review(binding, text, value => {
            if (!valid(binding)) return false;
            const original = binding.terminal && originalPastes.get(binding.terminal);
            if (original) { original(value); return true; }
            if (binding.terminal?.paste) { binding.terminal.paste(value); return true; }
            return root.SSHInput?.sendText(binding.id, value) || false;
        });
    }
    function attach(sessionId, terminal) {
        if (originalPastes.has(terminal)) return;
        originalPastes.set(terminal, terminal.paste.bind(terminal));
        terminal.paste = text => paste(capture(sessionId, terminal), text);
        terminal.element?.addEventListener('paste', event => {
            event.preventDefault();
            event.stopImmediatePropagation();
            paste(capture(sessionId, terminal), event.clipboardData?.getData('text/plain') || '');
        }, true);
    }
    root.TerminalPasteGuard = {capture, valid, label, needsReview, visibleText, trimTrailingNewlines, paste, review, attach, cancel, onWorkspaceChange};
    document.addEventListener('DOMContentLoaded', () => {
        const dialog = byId('terminalPasteDialog');
        dialog?.addEventListener('keydown', event => event.stopPropagation());
        dialog?.addEventListener('cancel', () => cancel());
        dialog?.addEventListener('close', () => { if (!dialog.open && pending) cancel(); });
        byId('terminalPasteCancel')?.addEventListener('click', () => cancel());
        byId('terminalPasteTrim')?.addEventListener('change', event => {
            if (pending) byId('terminalPastePreview').textContent = visibleText(event.target.checked ? trimTrailingNewlines(pending.text) : pending.text);
        });
        byId('terminalPasteConfirm')?.addEventListener('click', async () => {
            const request = pending;
            if (!request) return;
            if (!request.isCurrent()) { cancel(true); return; }
            const text = byId('terminalPasteTrim').checked ? trimTrailingNewlines(request.text) : request.text;
            pending = null;
            dialog.close();
            byId('terminalPastePreview').textContent = '';
            if (!request.isCurrent()) {
                request.resolve(false);
                notifyChanged(request.changedMessage);
                return;
            }
            try { request.resolve(text ? await request.send(text) : false); }
            catch { request.resolve(false); }
        });
    });
}(window));
