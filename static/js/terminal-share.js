/* Owner controls for link-based terminal sharing. */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (root) {
        root.TerminalShare = api;
        if (root.document?.getElementById('terminalShareModal')) {
            root.terminalShare = api.createController(root);
        }
    }
})(typeof window !== 'undefined' ? window : globalThis, function () {
    'use strict';

    function shareUrl(origin, appRoot, token) {
        const root = String(appRoot || '').replace(/\/+$/, '');
        return `${origin}${root}/share#${encodeURIComponent(token)}`;
    }

    function formatRemaining(seconds) {
        const total = Math.max(0, Math.floor(Number(seconds) || 0));
        const hours = Math.floor(total / 3600);
        const minutes = Math.floor((total % 3600) / 60);
        if (hours > 0) return `${hours}h ${String(minutes).padStart(2, '0')}m`;
        if (minutes > 0) return `${minutes}m`;
        return `${total}s`;
    }

    function initial(name) {
        const trimmed = String(name || '').trim();
        return trimmed ? Array.from(trimmed)[0].toUpperCase() : '?';
    }

    /** Return the owner-facing notice for a presence event, if any. */
    function describeEvent(event, t) {
        const name = String(event?.viewer || '');
        switch (event?.kind) {
        case 'joined':
            return { type: 'success', message: t('share.joined').replace('{name}', name) };
        case 'pending':
            return { type: 'info', message: t('share.pendingJoin').replace('{name}', name), approve: true };
        case 'left':
            return { type: 'info', message: t('share.left').replace('{name}', name) };
        default:
            return null;
        }
    }

    function errorMessage(code, t) {
        switch (code) {
        case 'sharing_disabled': return t('share.disabled');
        case 'control_disabled': return t('share.controlDisabled');
        case 'too_many_links': return t('share.tooManyLinks');
        case 'session_not_found': return t('share.noSession');
        default: return t('share.error');
        }
    }

    /** Compose a ready-to-paste invitation for ``share``. */
    function inviteText(share, { owner, url, remainingSeconds }, t) {
        const intro = t('share.inviteIntro')
            .replace('{owner}', owner || 'WebSSH')
            .replace('{title}', share.title);
        const access = share.mode === 'control'
            ? t('share.inviteAccessControl')
            : t('share.inviteAccessView');
        const expiry = t('share.inviteExpiry')
            .replace('{time}', formatRemaining(remainingSeconds));
        return `${intro}\n${url}\n${access} · ${expiry}`;
    }

    function viewerCount(shares) {
        return (shares || []).reduce(
            (total, share) => total + (share.viewers || []).filter(viewer => viewer.status === 'active').length,
            0,
        );
    }

    function createController(win) {
        const doc = win.document;
        const t = key => (win.i18n ? win.i18n.t(key) : key);
        const $ = id => doc.getElementById(id);
        const modal = $('terminalShareModal');
        const els = {
            button: $('shareTerminalBtn'),
            count: $('shareTerminalCount'),
            session: $('terminalShareSession'),
            form: $('terminalShareForm'),
            title: $('terminalShareLinkTitle'),
            ttl: $('terminalShareTtl'),
            maxViewers: $('terminalShareMaxViewers'),
            approval: $('terminalShareApproval'),
            controlOption: $('terminalShareControlOption'),
            create: $('terminalShareCreate'),
            links: $('terminalShareLinks'),
        };
        const state = {
            sessionId: null,
            sharesBySession: new Map(),
            limits: null,
            highlight: null,
            ticker: null,
            fetchedAt: Date.now(),
            openQr: new Set(),
        };
        const collab = win.WebSSHShareCollab;
        const QR = win.WebSSHQRCode;

        const appRoot = () => win.APP_ROOT || doc.querySelector('meta[name="app-root"]')?.content || '';
        const csrf = () => doc.querySelector('meta[name="csrf-token"]')?.content || '';
        const notify = (message, type = 'info', extra = {}) => win.showNotification?.({ message, type, ...extra });

        async function request(method, path, body) {
            const response = await win.fetch(`${appRoot()}${path}`, {
                method,
                credentials: 'same-origin',
                headers: {
                    Accept: 'application/json',
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrf(),
                },
                body: body === undefined ? undefined : JSON.stringify(body),
            });
            let payload = {};
            try {
                payload = await response.json();
            } catch {
                payload = {};
            }
            if (!response.ok || payload.success === false) {
                const error = new Error(payload.code || 'request_failed');
                error.code = payload.code;
                throw error;
            }
            return payload;
        }

        function sessionManager() {
            // session-manager.js declares a top-level `const`: a shared global
            // binding for classic scripts, but not a property of `window`.
            /* global SessionManager */
            return win.SessionManager
                || (typeof SessionManager !== 'undefined' ? SessionManager : null);
        }

        function activeSessionId() {
            const manager = sessionManager();
            const id = manager?.getWorkspaceSession?.() || manager?.getActiveSession?.() || null;
            const session = id ? manager?.sessions?.[id] : null;
            return session && session.connected !== false ? id : null;
        }

        function sessionLabel(sessionId) {
            const session = sessionManager()?.sessions?.[sessionId];
            if (!session) return '';
            return session.displayName || `${session.username}@${session.host}`;
        }

        // -----------------------------------------------------------------
        // Badges
        // -----------------------------------------------------------------
        function renderBadges() {
            let total = 0;
            for (const [sessionId, shares] of state.sharesBySession) {
                const tab = doc.getElementById(`tab-${sessionId}`);
                const count = viewerCount(shares);
                total += count;
                if (!tab) continue;
                let badge = tab.querySelector('.tab-share-badge');
                if (!shares.length) {
                    badge?.remove();
                    continue;
                }
                if (!badge) {
                    badge = doc.createElement('span');
                    badge.className = 'tab-share-badge';
                    badge.innerHTML = '<span class="material-icons" aria-hidden="true">podcasts</span><span class="tab-share-badge-count"></span>';
                    const label = tab.querySelector('.tab-label');
                    label?.after(badge);
                }
                // Writes only on change: the tab observer watches this subtree.
                if (badge.title !== t('share.sharedBadge')) badge.title = t('share.sharedBadge');
                badge.classList.toggle('has-viewers', count > 0);
                const countNode = badge.querySelector('.tab-share-badge-count');
                const countText = count > 0 ? String(count) : '';
                if (countNode.textContent !== countText) countNode.textContent = countText;
            }
            if (els.count) {
                els.count.textContent = String(total);
                els.count.hidden = total === 0;
            }
            els.button?.classList.toggle('is-sharing', state.sharesBySession.size > 0
                && Array.from(state.sharesBySession.values()).some(shares => shares.length > 0));
            syncCollab();
        }

        function storeShares(sessionId, shares) {
            if (shares?.length) {
                state.sharesBySession.set(sessionId, shares);
            } else {
                state.sharesBySession.delete(sessionId);
            }
            state.fetchedAt = Date.now();
            renderBadges();
        }

        // -----------------------------------------------------------------
        // Dialog rendering
        // -----------------------------------------------------------------
        function renderLimits() {
            const limits = state.limits;
            if (!limits) return;
            const current = Number(els.maxViewers.value) || Math.min(3, limits.max_viewers_per_link);
            els.maxViewers.innerHTML = '';
            for (let count = 1; count <= limits.max_viewers_per_link; count += 1) {
                const option = doc.createElement('option');
                option.value = String(count);
                option.textContent = String(count);
                option.selected = count === Math.min(current, limits.max_viewers_per_link);
                els.maxViewers.appendChild(option);
            }
            for (const option of els.ttl.options) {
                option.disabled = Number(option.value) > limits.max_ttl_minutes;
            }
            if (els.ttl.selectedOptions[0]?.disabled) {
                els.ttl.value = String(Math.min(limits.default_ttl_minutes, limits.max_ttl_minutes));
            }
            const control = els.controlOption.querySelector('input');
            control.disabled = !limits.allow_control;
            els.controlOption.classList.toggle('is-disabled', !limits.allow_control);
            if (!limits.allow_control) {
                els.form.querySelector('input[value="view"]').checked = true;
            }
        }

        function element(tag, className, text) {
            const node = doc.createElement(tag);
            if (className) node.className = className;
            if (text !== undefined) node.textContent = text;
            return node;
        }

        function iconButton(icon, label, className, onClick) {
            const button = element('button', className);
            button.type = 'button';
            button.title = label;
            button.setAttribute('aria-label', label);
            const glyph = element('span', 'material-icons', icon);
            glyph.setAttribute('aria-hidden', 'true');
            button.appendChild(glyph);
            button.addEventListener('click', onClick);
            return button;
        }

        function renderViewer(share, viewer) {
            const item = element('li', `share-viewer is-${viewer.status}`);
            item.dataset.viewerId = viewer.id;
            const avatar = element('span', 'share-viewer-avatar', initial(viewer.name));
            avatar.setAttribute('aria-hidden', 'true');
            const copy = element('span', 'share-viewer-copy');
            copy.appendChild(element('strong', '', viewer.name));
            const status = viewer.status === 'pending'
                ? t('share.waiting')
                : viewer.connected ? t('share.connected') : t('share.away');
            const statusClass = viewer.status === 'pending' ? 'is-pending' : viewer.connected ? 'is-online' : '';
            copy.appendChild(element('small', `share-viewer-status ${statusClass}`, status));
            item.append(avatar, copy);
            if (viewer.typed) {
                item.appendChild(element('span', 'share-chip share-chip-info', t('share.typed')));
            }
            const actions = element('span', 'share-viewer-actions');
            if (viewer.status === 'pending') {
                const admit = element('button', 'btn btn-primary btn-sm share-admit', t('share.approve'));
                admit.type = 'button';
                admit.addEventListener('click', () => approve(share.id, viewer.id));
                actions.appendChild(admit);
            }
            actions.appendChild(iconButton('person_remove', t('share.remove'), 'share-icon-btn', () => removeViewer(share.id, viewer.id)));
            item.appendChild(actions);
            return item;
        }

        function remainingSeconds(share) {
            return share.expires_in - (Date.now() - state.fetchedAt) / 1000;
        }

        function renderShare(share) {
            const card = element('article', 'share-link');
            card.dataset.shareId = share.id;
            if (state.highlight === share.id) card.classList.add('is-new');

            const header = element('header', 'share-link-header');
            const heading = element('div', 'share-link-heading');
            const dot = element('span', 'share-live-dot');
            dot.setAttribute('aria-hidden', 'true');
            heading.append(dot, element('strong', 'share-link-title', share.title));
            const mode = element(
                'span',
                `share-chip ${share.mode === 'control' ? 'share-chip-control' : ''}`,
                share.mode === 'control' ? t('share.modeControl') : t('share.modeView'),
            );
            heading.appendChild(mode);
            header.appendChild(heading);
            const expiry = element('span', 'share-expiry');
            expiry.dataset.expiry = '';
            expiry.textContent = t('share.expiresIn').replace('{time}', formatRemaining(remainingSeconds(share)));
            header.appendChild(expiry);
            card.appendChild(header);

            const urlRow = element('div', 'share-url-row');
            const input = element('input', 'share-url');
            input.type = 'text';
            input.readOnly = true;
            input.value = shareUrl(win.location.origin, appRoot(), share.token);
            input.setAttribute('aria-label', t('share.copy'));
            input.addEventListener('focus', () => input.select());
            const copy = element('button', 'btn btn-secondary share-copy');
            copy.type = 'button';
            const copyIcon = element('span', 'material-icons', 'content_copy');
            copyIcon.setAttribute('aria-hidden', 'true');
            copy.append(copyIcon, element('span', '', t('share.copy')));
            copy.addEventListener('click', () => copyLink(input.value, copy));
            urlRow.append(input, copy);
            card.appendChild(urlRow);
            card.appendChild(renderLinkActions(share, input.value));

            const controls = element('div', 'share-link-controls');
            if (state.limits?.allow_control !== false) {
                const toggle = element('label', 'share-switch share-switch-inline');
                const checkbox = element('input');
                checkbox.type = 'checkbox';
                checkbox.checked = share.mode === 'control';
                checkbox.addEventListener('change', () => setMode(share.id, checkbox.checked ? 'control' : 'view', checkbox));
                const track = element('span', 'share-switch-track');
                track.setAttribute('aria-hidden', 'true');
                toggle.append(checkbox, track, element('span', 'share-switch-label', t('share.allowTyping')));
                controls.appendChild(toggle);
            }
            const stop = element('button', 'btn btn-danger-ghost share-stop');
            stop.type = 'button';
            const stopIcon = element('span', 'material-icons', 'stop_circle');
            stopIcon.setAttribute('aria-hidden', 'true');
            stop.append(stopIcon, element('span', '', t('share.revoke')));
            stop.addEventListener('click', () => revoke(share.id));
            controls.appendChild(stop);
            card.appendChild(controls);

            const viewers = element('ul', 'share-viewers');
            if (share.viewers?.length) {
                for (const viewer of share.viewers) viewers.appendChild(renderViewer(share, viewer));
            } else {
                viewers.appendChild(element('li', 'share-viewers-empty', t('share.noViewers')));
            }
            card.appendChild(viewers);
            return card;
        }

        function actionButton(icon, label, onClick) {
            const button = element('button', 'share-action');
            button.type = 'button';
            const glyph = element('span', 'material-icons', icon);
            glyph.setAttribute('aria-hidden', 'true');
            button.append(glyph, element('span', '', label));
            button.addEventListener('click', onClick);
            return button;
        }

        function ownerName() {
            return doc.querySelector('.account-name')?.textContent.trim() || '';
        }

        function renderLinkActions(share, url) {
            const wrapper = element('div', 'share-link-extras');
            const actions = element('div', 'share-link-actions');
            const qrPanel = element('div', 'share-qr');
            qrPanel.id = `shareQr-${share.id}`;
            const qrButton = actionButton('qr_code_2', t('share.qrShow'), () => {
                const opening = qrPanel.hidden;
                if (opening && !qrPanel.firstChild) renderQr(qrPanel, url);
                qrPanel.hidden = !opening;
                qrButton.setAttribute('aria-expanded', String(opening));
                if (opening) state.openQr.add(share.id);
                else state.openQr.delete(share.id);
            });
            qrButton.setAttribute('aria-controls', qrPanel.id);
            const invite = () => inviteText(share, {
                owner: ownerName(),
                url,
                remainingSeconds: remainingSeconds(share),
            }, t);
            const inviteButton = actionButton('forward_to_inbox', t('share.copyInvite'), async () => {
                try {
                    await win.navigator.clipboard.writeText(invite());
                    notify(t('share.inviteCopied'), 'success');
                    inviteButton.classList.add('is-copied');
                    win.setTimeout(() => inviteButton.classList.remove('is-copied'), 1400);
                } catch {
                    notify(t('share.error'), 'error');
                }
            });
            actions.append(qrButton, inviteButton);
            if (typeof win.navigator?.share === 'function') {
                actions.appendChild(actionButton('ios_share', t('share.nativeShare'), () => {
                    win.navigator.share({ title: share.title, text: invite(), url }).catch(() => {});
                }));
            }
            const keepOpen = state.openQr.has(share.id);
            qrPanel.hidden = !keepOpen;
            qrButton.setAttribute('aria-expanded', String(keepOpen));
            if (keepOpen) renderQr(qrPanel, url);
            wrapper.append(actions, qrPanel);
            return wrapper;
        }

        function renderQr(panel, url) {
            panel.replaceChildren();
            if (!QR) return;
            try {
                const figure = element('div', 'share-qr-code');
                figure.appendChild(QR.toSvgElement(doc, url, { label: t('share.qrShow') }));
                panel.append(figure, element('p', 'share-qr-hint', t('share.qrHint')));
            } catch {
                panel.appendChild(element('p', 'share-qr-hint', t('share.error')));
            }
        }

        function renderList() {
            const shares = state.sharesBySession.get(state.sessionId) || [];
            modal.querySelector('.share-modal-body')?.classList.toggle('has-links', shares.length > 0);
            els.links.replaceChildren();
            if (!shares.length) {
                const empty = element('div', 'share-empty');
                const icon = element('span', 'material-icons', 'link');
                icon.setAttribute('aria-hidden', 'true');
                empty.append(icon, element('span', '', t('share.noLinks')));
                els.links.appendChild(empty);
                return;
            }
            for (const share of shares.slice().reverse()) {
                els.links.appendChild(renderShare(share));
            }
            state.highlight = null;
        }

        function tickExpiry() {
            if (!modal.classList.contains('show')) return;
            const shares = state.sharesBySession.get(state.sessionId) || [];
            for (const share of shares) {
                const node = els.links.querySelector(`[data-share-id="${CSS.escape(share.id)}"] [data-expiry]`);
                if (node) node.textContent = t('share.expiresIn').replace('{time}', formatRemaining(remainingSeconds(share)));
            }
        }

        // -----------------------------------------------------------------
        // Actions
        // -----------------------------------------------------------------
        async function refresh(sessionId = state.sessionId) {
            const query = sessionId ? `?session_id=${encodeURIComponent(sessionId)}` : '';
            const payload = await request('GET', `/api/terminal-shares${query}`);
            state.limits = payload.limits;
            if (sessionId) {
                storeShares(sessionId, payload.shares);
            } else {
                state.sharesBySession.clear();
                for (const share of payload.shares) {
                    const list = state.sharesBySession.get(share.session_id) || [];
                    list.push(share);
                    state.sharesBySession.set(share.session_id, list);
                }
                state.fetchedAt = Date.now();
                renderBadges();
            }
            return payload;
        }

        async function open(sessionId = activeSessionId()) {
            if (!sessionId) {
                notify(t('share.noSession'), 'warning');
                return false;
            }
            state.sessionId = sessionId;
            els.session.textContent = sessionLabel(sessionId);
            els.title.value = sessionManager()?.sessions?.[sessionId]?.displayName || '';
            renderList();
            win.ModalManager?.open(modal);
            win.setTimeout(() => els.title.focus(), 30);
            try {
                await refresh(sessionId);
                renderLimits();
                renderList();
            } catch (error) {
                notify(errorMessage(error.code, t), 'error');
            }
            win.clearInterval(state.ticker);
            state.ticker = win.setInterval(tickExpiry, 15000);
            return true;
        }

        function close() {
            win.clearInterval(state.ticker);
            win.ModalManager?.close(modal);
        }

        async function copyLink(url, button) {
            try {
                await win.navigator.clipboard.writeText(url);
                notify(t('share.copied'), 'success');
                if (button) {
                    button.classList.add('is-copied');
                    win.setTimeout(() => button.classList.remove('is-copied'), 1400);
                }
            } catch {
                const input = button?.parentElement?.querySelector('input');
                input?.focus();
                input?.select();
            }
        }

        async function create(event) {
            event?.preventDefault();
            if (!state.sessionId) return;
            els.create.disabled = true;
            try {
                const mode = els.form.querySelector('input[name="terminalShareMode"]:checked')?.value || 'view';
                const payload = await request('POST', '/api/terminal-shares', {
                    session_id: state.sessionId,
                    title: els.title.value.trim(),
                    mode,
                    ttl_minutes: Number(els.ttl.value),
                    max_viewers: Number(els.maxViewers.value),
                    require_approval: els.approval.checked,
                });
                state.highlight = payload.share.id;
                const shares = (state.sharesBySession.get(state.sessionId) || [])
                    .filter(share => share.id !== payload.share.id)
                    .concat(payload.share);
                storeShares(state.sessionId, shares);
                renderList();
                copyLink(shareUrl(win.location.origin, appRoot(), payload.share.token));
            } catch (error) {
                notify(errorMessage(error.code, t), 'error');
            } finally {
                els.create.disabled = false;
            }
        }

        async function mutate(method, path, body) {
            try {
                await request(method, path, body);
            } catch (error) {
                notify(errorMessage(error.code, t), 'error');
            }
            try {
                await refresh(state.sessionId);
                renderList();
            } catch {
                // The next presence event refreshes the list.
            }
        }

        function revoke(shareId) {
            return mutate('DELETE', `/api/terminal-shares/${encodeURIComponent(shareId)}`)
                .then(() => notify(t('share.revoked'), 'info'));
        }

        function setMode(shareId, mode, checkbox) {
            if (checkbox) checkbox.disabled = true;
            return mutate('PATCH', `/api/terminal-shares/${encodeURIComponent(shareId)}`, { mode });
        }

        function approve(shareId, viewerId) {
            return mutate(
                'POST',
                `/api/terminal-shares/${encodeURIComponent(shareId)}/viewers/${encodeURIComponent(viewerId)}/approve`,
            );
        }

        function removeViewer(shareId, viewerId) {
            return mutate(
                'DELETE',
                `/api/terminal-shares/${encodeURIComponent(shareId)}/viewers/${encodeURIComponent(viewerId)}`,
            );
        }

        function findPending(shares, name) {
            for (const share of shares || []) {
                const viewer = (share.viewers || []).find(item => item.status === 'pending' && item.name === name);
                if (viewer) return { shareId: share.id, viewerId: viewer.id };
            }
            return null;
        }

        function handleUpdate(payload) {
            if (!payload?.session_id) return;
            storeShares(payload.session_id, payload.shares || []);
            if (modal.classList.contains('show') && payload.session_id === state.sessionId) {
                renderList();
            }
            const notice = describeEvent(payload.event, t);
            if (!notice) return;
            const extra = {};
            if (notice.approve) {
                const pending = findPending(payload.shares, payload.event.viewer);
                if (pending) {
                    extra.persistent = true;
                    extra.action = {
                        label: t('share.approve'),
                        onClick: () => approve(pending.shareId, pending.viewerId),
                    };
                }
            }
            notify(notice.message, notice.type, extra);
        }

        // -----------------------------------------------------------------
        // Session chat and pointers
        // -----------------------------------------------------------------
        const chat = {
            root: $('shareCollab'),
            toggle: $('shareCollabToggle'),
            badge: $('shareCollabBadge'),
            panel: $('shareCollabPanel'),
            session: $('shareCollabSession'),
            point: $('shareCollabPoint'),
            close: $('shareCollabClose'),
            hint: $('shareCollabPointerHint'),
            list: $('shareCollabList'),
            empty: $('shareCollabEmpty'),
            form: $('shareCollabForm'),
            input: $('shareCollabInput'),
            logs: new Map(),
            unread: new Map(),
            loaded: new Set(),
            sessionId: null,
            open: false,
            pointing: false,
        };

        function terminalManager() {
            /* global TerminalManager */
            return win.TerminalManager
                || (typeof TerminalManager !== 'undefined' ? TerminalManager : null);
        }

        function chatLogFor(sessionId) {
            if (!chat.logs.has(sessionId)) chat.logs.set(sessionId, collab.createChatLog());
            return chat.logs.get(sessionId);
        }

        function chatAvailable(sessionId) {
            return Boolean(
                collab
                && chat.root
                && sessionId
                && state.limits?.chat !== false
                && (state.sharesBySession.get(sessionId) || []).length,
            );
        }

        function syncCollab() {
            if (!chat.root) return;
            const sessionId = activeSessionId();
            const available = chatAvailable(sessionId);
            chat.root.hidden = !available;
            if (!available) {
                setCollabOpen(false);
                setPointing(false);
                chat.sessionId = null;
                return;
            }
            if (chat.sessionId !== sessionId) {
                chat.sessionId = sessionId;
                chat.session.textContent = sessionLabel(sessionId);
                setPointing(false);
                renderChat();
                if (chat.open) loadHistory(sessionId);
            }
            const unread = chat.unread.get(sessionId) || 0;
            chat.badge.textContent = unread > 9 ? '9+' : String(unread);
            chat.badge.hidden = unread === 0;
        }

        function renderChat() {
            if (!chat.sessionId) return;
            const messages = chatLogFor(chat.sessionId).list();
            chat.list.replaceChildren(...messages.map(message => collab.renderMessage(doc, message, {
                self: message.role === 'owner',
                labels: { you: t('share.chatYou') },
                locale: win.i18n?.getLanguage?.(),
            })));
            chat.empty.hidden = messages.length > 0;
            chat.list.scrollTop = chat.list.scrollHeight;
        }

        async function loadHistory(sessionId) {
            try {
                const payload = await request(
                    'GET',
                    `/api/terminal-shares/chat?session_id=${encodeURIComponent(sessionId)}`,
                );
                const log = chatLogFor(sessionId);
                const pending = log.list();
                log.replace(payload.messages);
                pending.forEach(message => log.add(message));
                chat.loaded.add(sessionId);
                if (chat.sessionId === sessionId) renderChat();
            } catch {
                // Live events still arrive; history is a convenience.
            }
        }

        function setCollabOpen(open) {
            if (!chat.root) return;
            chat.open = Boolean(open) && !chat.root.hidden;
            chat.panel.hidden = !chat.open;
            chat.toggle.setAttribute('aria-expanded', String(chat.open));
            chat.root.classList.toggle('is-open', chat.open);
            if (!chat.open) {
                setPointing(false);
                return;
            }
            chat.unread.set(chat.sessionId, 0);
            syncCollab();
            renderChat();
            if (!chat.loaded.has(chat.sessionId)) loadHistory(chat.sessionId);
            win.setTimeout(() => chat.input.focus(), 30);
        }

        function receiveChat(payload) {
            const sessionId = payload?.session_id;
            const message = payload?.chat;
            if (!sessionId || !message || !collab) return;
            if (!chatLogFor(sessionId).add(message)) return;
            if (chat.open && chat.sessionId === sessionId) {
                renderChat();
                return;
            }
            if (message.role === 'owner') return;
            chat.unread.set(sessionId, (chat.unread.get(sessionId) || 0) + 1);
            syncCollab();
            notify(
                t('share.chatFrom').replace('{name}', message.name).replace('{message}', message.text),
                'info',
                {
                    duration: 5000,
                    action: {
                        label: t('share.chatReply'),
                        onClick: () => setCollabOpen(true),
                    },
                },
            );
        }

        async function sendChat() {
            const text = chat.input.value.trim().slice(0, 500);
            if (!text || !chat.sessionId) return;
            try {
                const payload = await request('POST', '/api/terminal-shares/chat', {
                    session_id: chat.sessionId,
                    text,
                });
                chat.input.value = '';
                chatLogFor(chat.sessionId).add(payload.message);
                renderChat();
            } catch {
                chat.form.classList.remove('is-error');
                void chat.form.offsetWidth;
                chat.form.classList.add('is-error');
                chat.input.title = t('share.chatFailed');
                win.setTimeout(() => chat.form.classList.remove('is-error'), 1200);
            }
        }

        function visibleTerminals(sessionId) {
            const manager = terminalManager();
            return (manager?.sessionTerminals?.[sessionId] || [])
                .filter(key => manager.isTerminalKeyVisible?.(key))
                .map(key => manager.terminals[key])
                .filter(term => term?.element);
        }

        function placePointer(sessionId, pointer, self = false) {
            for (const term of visibleTerminals(sessionId)) {
                const screen = term.element.querySelector('.xterm-screen');
                const rect = screen?.getBoundingClientRect();
                const box = collab.cellBox(rect, collab.terminalGrid(term), pointer.col, pointer.row);
                if (!box) continue;
                let layer = term.element.querySelector(':scope > .cv-pointer-layer');
                if (!layer) {
                    layer = element('div', 'cv-pointer-layer');
                    term.element.appendChild(layer);
                }
                const origin = term.element.getBoundingClientRect();
                collab.showPointer(doc, layer, {
                    ...box,
                    left: box.left + rect.left - origin.left,
                    top: box.top + rect.top - origin.top,
                }, {
                    name: self ? t('share.chatYou') : pointer.name,
                    role: pointer.role,
                    self,
                });
            }
        }

        function setPointing(on) {
            if (!chat.root) return;
            chat.pointing = Boolean(on) && Boolean(chat.sessionId);
            chat.point.setAttribute('aria-pressed', String(chat.pointing));
            chat.hint.hidden = !chat.pointing;
            doc.body.classList.toggle('share-pointing', chat.pointing);
        }

        doc.addEventListener('pointerdown', event => {
            if (!chat.pointing || !chat.sessionId) return;
            const xterm = event.target?.closest?.('.xterm');
            const term = xterm && visibleTerminals(chat.sessionId).find(item => item.element === xterm);
            if (!term) return;
            event.preventDefault();
            event.stopPropagation();
            const rect = term.element.querySelector('.xterm-screen')?.getBoundingClientRect();
            const cell = collab.cellFromPoint(rect, collab.terminalGrid(term), event.clientX, event.clientY);
            if (!cell) return;
            placePointer(chat.sessionId, { ...cell, role: 'owner' }, true);
            request('POST', '/api/terminal-shares/pointer', {
                session_id: chat.sessionId,
                ...cell,
            }).catch(() => {});
        }, true);

        doc.addEventListener('keydown', event => {
            if (event.key === 'Escape' && chat.pointing) {
                event.preventDefault();
                event.stopImmediatePropagation();
                setPointing(false);
            }
        }, true);

        if (chat.root && collab) {
            chat.toggle.addEventListener('click', () => setCollabOpen(!chat.open));
            chat.close.addEventListener('click', () => setCollabOpen(false));
            chat.point.addEventListener('click', () => setPointing(!chat.pointing));
            chat.form.addEventListener('submit', event => {
                event.preventDefault();
                sendChat();
            });
        }

        // -----------------------------------------------------------------
        // Wiring
        // -----------------------------------------------------------------
        els.button?.addEventListener('click', () => open());
        doc.getElementById('mobileShareAction')?.addEventListener('click', () => {
            win.mobileAppShell?.closeMoreMenu?.();
            open();
        });
        doc.getElementById('closeTerminalShareModal')?.addEventListener('click', close);
        modal.addEventListener('click', event => {
            if (event.target === modal) close();
        });
        els.form.addEventListener('submit', create);

        const socket = win.socket;
        if (socket?.on) {
            socket.on('terminal_share_update', handleUpdate);
            socket.on('connect', () => {
                refresh(null).catch(() => {});
            });
            socket.on('ssh_disconnected', data => {
                if (data?.session_id) storeShares(data.session_id, []);
            });
            socket.on('terminal_share_chat', receiveChat);
            socket.on('terminal_share_pointer', payload => {
                if (payload?.session_id && payload.pointer && collab) {
                    placePointer(payload.session_id, payload.pointer);
                }
            });
        }
        win.addEventListener('languageChanged', () => {
            renderBadges();
            if (modal.classList.contains('show')) renderList();
        });
        // Session tabs are rebuilt on restore and reconnect; keep badges on
        // them, and calm the entry point while there is nothing to share.
        const tabs = doc.getElementById('sessionTabs');
        const syncIdle = () => {
            els.button?.classList.toggle('is-idle', !tabs?.querySelector('.session-tab'));
        };
        syncIdle();
        if (tabs && typeof win.MutationObserver === 'function') {
            let pending = false;
            new win.MutationObserver(() => {
                if (pending) return;
                pending = true;
                win.requestAnimationFrame(() => {
                    pending = false;
                    syncIdle();
                    if (state.sharesBySession.size) renderBadges();
                    else syncCollab();
                });
            }).observe(tabs, {
                childList: true,
                subtree: true,
                attributes: true,
                attributeFilter: ['class'],
            });
        }

        return {
            open,
            close,
            refresh,
            handleUpdate,
            openChat: () => setCollabOpen(true),
            state,
        };
    }

    return {
        createController,
        describeEvent,
        errorMessage,
        formatRemaining,
        initial,
        inviteText,
        shareUrl,
        viewerCount,
    };
});
