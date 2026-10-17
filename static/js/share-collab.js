/* Shared chat and pointer helpers for terminal owners and share guests. */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (root) {
        root.WebSSHShareCollab = api;
    }
})(typeof window !== 'undefined' ? window : globalThis, function () {
    'use strict';

    const POINTER_LIFETIME_MS = 3200;

    /**
     * Pointers address the live screen (row 0 is the top of what a fully
     * scrolled-down terminal shows), never scrollback: owner and guests share
     * the same screen, but not the same history.
     */
    function terminalGrid(term) {
        const buffer = term?.buffer?.active;
        return {
            cols: term?.cols || 0,
            rows: term?.rows || 0,
            viewportY: buffer?.viewportY || 0,
            baseY: buffer?.baseY || 0,
        };
    }

    /** Map a click inside the terminal screen to a live-screen cell. */
    function cellFromPoint(rect, grid, x, y) {
        if (!rect?.width || !rect?.height || !grid.cols || !grid.rows) return null;
        const col = Math.floor((x - rect.left) / (rect.width / grid.cols));
        const viewRow = Math.floor((y - rect.top) / (rect.height / grid.rows));
        if (col < 0 || col >= grid.cols || viewRow < 0 || viewRow >= grid.rows) return null;
        const row = grid.viewportY + viewRow - grid.baseY;
        if (row < 0 || row >= grid.rows) return null;
        return { col, row };
    }

    /** Return a cell's box relative to the screen, or null when scrolled away. */
    function cellBox(rect, grid, col, row) {
        if (!rect?.width || !rect?.height || !grid.cols || !grid.rows) return null;
        const viewRow = grid.baseY + row - grid.viewportY;
        if (col < 0 || col >= grid.cols || viewRow < 0 || viewRow >= grid.rows) return null;
        const width = rect.width / grid.cols;
        const height = rect.height / grid.rows;
        return { left: col * width, top: viewRow * height, width, height };
    }

    /** Ordered, de-duplicated message log; IDs are server-assigned. */
    function createChatLog(limit = 200) {
        let messages = [];
        const ids = new Set();
        return {
            add(message) {
                if (!message || typeof message.id !== 'number' || ids.has(message.id)) return false;
                ids.add(message.id);
                messages.push(message);
                if (messages.length > 1 && messages[messages.length - 2].id > message.id) {
                    messages.sort((left, right) => left.id - right.id);
                }
                while (messages.length > limit) ids.delete(messages.shift().id);
                return true;
            },
            replace(list) {
                messages = [];
                ids.clear();
                (Array.isArray(list) ? list : []).forEach(item => this.add(item));
            },
            list() {
                return messages.slice();
            },
            get size() {
                return messages.length;
            },
        };
    }

    function formatClock(iso, locale) {
        const date = new Date(iso);
        if (Number.isNaN(date.getTime())) return '';
        try {
            return date.toLocaleTimeString(locale || undefined, { hour: '2-digit', minute: '2-digit' });
        } catch {
            return date.toISOString().slice(11, 16);
        }
    }

    /** Render one message; every value is set as text, never as markup. */
    function renderMessage(doc, message, { self = false, labels = {}, locale } = {}) {
        const item = doc.createElement('li');
        item.className = 'cv-message';
        item.classList.toggle('is-self', self);
        item.classList.toggle('is-owner', message.role === 'owner');
        item.dataset.messageId = String(message.id);
        const meta = doc.createElement('div');
        meta.className = 'cv-message-meta';
        const name = doc.createElement('strong');
        name.textContent = self ? (labels.you || 'You') : message.name;
        meta.appendChild(name);
        if (message.role === 'owner' && !self && labels.owner) {
            const badge = doc.createElement('span');
            badge.className = 'cv-role';
            badge.textContent = labels.owner;
            meta.appendChild(badge);
        }
        const time = doc.createElement('time');
        time.dateTime = message.at || '';
        time.textContent = formatClock(message.at, locale);
        meta.appendChild(time);
        const body = doc.createElement('p');
        body.className = 'cv-message-text';
        body.textContent = message.text;
        item.append(meta, body);
        return item;
    }

    /** Show a short-lived pointer marker inside ``layer`` at ``box``. */
    function showPointer(doc, layer, box, { name, role, self = false, lifetime = POINTER_LIFETIME_MS } = {}) {
        if (!layer || !box) return null;
        const marker = doc.createElement('div');
        marker.className = `cv-pointer ${role === 'owner' ? 'is-owner' : 'is-guest'}${self ? ' is-self' : ''}`;
        // Keep the name inside the terminal for cells on the first rows.
        marker.classList.toggle('label-below', box.top < 28);
        marker.style.left = `${box.left}px`;
        marker.style.top = `${box.top}px`;
        marker.style.width = `${Math.max(box.width, 6)}px`;
        marker.style.height = `${Math.max(box.height, 6)}px`;
        marker.setAttribute('aria-hidden', 'true');
        const label = doc.createElement('span');
        label.className = 'cv-pointer-label';
        label.textContent = name || '';
        marker.appendChild(label);
        layer.appendChild(marker);
        const timer = setTimeout(() => {
            marker.classList.add('is-leaving');
            setTimeout(() => marker.remove(), 400);
        }, lifetime);
        marker.addEventListener('click', () => {
            clearTimeout(timer);
            marker.remove();
        });
        return marker;
    }

    return {
        POINTER_LIFETIME_MS,
        cellBox,
        cellFromPoint,
        createChatLog,
        formatClock,
        renderMessage,
        showPointer,
        terminalGrid,
    };
});
