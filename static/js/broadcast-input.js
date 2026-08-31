/*
 * Broadcast input — a dedicated input bar whose content is sent to EVERY open
 * (connected) SSH session at once (cluster-SSH style), independent of which
 * terminal is focused. Pure client-side: each target still goes through the
 * existing, ownership-checked `ssh_input` handler.
 */
(function () {
    'use strict';

    function connectedSessions() {
        if (typeof SessionManager === 'undefined' || !SessionManager.getAllSessions) {
            return [];
        }
        return SessionManager.getAllSessions().filter(s => s && s.connected);
    }

    const BroadcastInput = {
        open: false,

        toggle() {
            this.open ? this.close() : this.show();
        },

        show() {
            this.open = true;
            document.body.classList.add('broadcast-active');
            const bar = document.getElementById('broadcastBar');
            const btn = document.getElementById('broadcastToggleBtn');
            const input = document.getElementById('broadcastInput');
            if (bar) bar.classList.remove('hidden');
            if (btn) {
                btn.classList.add('active');
                btn.setAttribute('aria-pressed', 'true');
            }
            this.updateCount();
            if (input) input.focus();
        },

        close() {
            this.open = false;
            document.body.classList.remove('broadcast-active');
            const bar = document.getElementById('broadcastBar');
            const btn = document.getElementById('broadcastToggleBtn');
            if (bar) bar.classList.add('hidden');
            if (btn) {
                btn.classList.remove('active');
                btn.setAttribute('aria-pressed', 'false');
            }
        },

        updateCount() {
            const el = document.getElementById('broadcastCount');
            if (el) el.textContent = String(connectedSessions().length);
        },

        // Send the given text (plus a carriage return) to every connected session.
        sendAll(text) {
            if (!window.socket) return 0;
            const sessions = connectedSessions();
            sessions.forEach(s => {
                const data = text + '\r';
                if (window.SSHInput) {
                    window.SSHInput.send(s.id, data);
                } else {
                    window.socket.emit('ssh_input', { session_id: s.id, data });
                }
            });
            return sessions.length;
        }
    };

    window.BroadcastInput = BroadcastInput;

    document.addEventListener('DOMContentLoaded', () => {
        const toggle = document.getElementById('broadcastToggleBtn');
        const input = document.getElementById('broadcastInput');
        const sendBtn = document.getElementById('broadcastSendBtn');
        const closeBtn = document.getElementById('broadcastCloseBtn');

        const submit = () => {
            if (!input || input.value === '') return;
            const count = BroadcastInput.sendAll(input.value);
            input.value = '';
            input.focus();
            if (window.showNotification && window.i18n) {
                showNotification(i18n.t('broadcast.sent').replace('{n}', count), 'info');
            }
        };

        if (toggle) toggle.addEventListener('click', () => BroadcastInput.toggle());
        if (sendBtn) sendBtn.addEventListener('click', submit);
        if (closeBtn) closeBtn.addEventListener('click', () => BroadcastInput.close());
        if (input) {
            input.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    submit();
                } else if (e.key === 'Escape') {
                    e.preventDefault();
                    BroadcastInput.close();
                }
            });
            // Keep the session counter fresh while the bar is open.
            input.addEventListener('focus', () => BroadcastInput.updateCount());
        }
    });
})();
