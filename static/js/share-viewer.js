/* Public viewer for a shared WebSSH terminal. */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (root) {
        root.WebSSHShareViewer = api;
    }
    if (typeof document !== 'undefined' && document.body?.classList.contains('sv')) {
        api.boot(root);
    }
})(typeof window !== 'undefined' ? window : globalThis, function () {
    'use strict';

    const TICKET_STORAGE_KEY = 'webssh.share.seat';
    const NAME_STORAGE_KEY = 'webssh.share.name';
    const MAX_INPUT_CHUNK = 16 * 1024;
    const MAX_PENDING_INPUT = 256 * 1024;

    // Literal keys keep the generated translation bundle complete.
    const REASON_KEYS = {
        revoked: 'share.viewer.reason.revoked',
        expired: 'share.viewer.reason.expired',
        session_closed: 'share.viewer.reason.sessionClosed',
        removed: 'share.viewer.reason.removed',
        owner_signed_out: 'share.viewer.reason.ownerSignedOut',
        left: 'share.viewer.reason.left',
        timed_out: 'share.viewer.reason.timedOut',
        link_invalid: 'share.viewer.reason.linkInvalid',
        ticket_invalid: 'share.viewer.reason.linkInvalid',
        share_full: 'share.viewer.reason.shareFull',
        capacity: 'share.viewer.reason.capacity',
        sharing_disabled: 'share.viewer.reason.disabled',
        rate_limited: 'share.viewer.reason.rateLimited',
        no_link: 'share.viewer.noLink',
    };
    const REJOINABLE = new Set([
        'left', 'timed_out', 'share_full', 'capacity', 'rate_limited', 'unknown',
    ]);
    const UNAVAILABLE = new Set(['link_invalid', 'ticket_invalid', 'no_link', 'sharing_disabled']);

    function reasonKey(reason) {
        return REASON_KEYS[reason] || 'share.viewer.reason.unknown';
    }

    /** Incremental parser for a `text/event-stream` body. */
    function createEventStreamParser(onEvent) {
        let buffer = '';
        return {
            push(text) {
                buffer += text;
                let boundary = buffer.indexOf('\n\n');
                while (boundary >= 0) {
                    const block = buffer.slice(0, boundary);
                    buffer = buffer.slice(boundary + 2);
                    let event = 'message';
                    let id = null;
                    const data = [];
                    for (const line of block.split('\n')) {
                        if (!line || line.startsWith(':')) continue;
                        const colon = line.indexOf(':');
                        const field = colon < 0 ? line : line.slice(0, colon);
                        let value = colon < 0 ? '' : line.slice(colon + 1);
                        if (value.startsWith(' ')) value = value.slice(1);
                        if (field === 'event') event = value;
                        else if (field === 'data') data.push(value);
                        else if (field === 'id') id = value;
                    }
                    if (data.length) {
                        onEvent({ event, id, data: data.join('\n') });
                    }
                    boundary = buffer.indexOf('\n\n');
                }
            },
            pendingLength() {
                return buffer.length;
            },
        };
    }

    /**
     * Ordered keystroke delivery with one request in flight. Keys typed while a
     * request is pending are coalesced into the next one.
     */
    function createInputQueue(send, options = {}) {
        const wait = options.wait || (ms => new Promise(resolve => setTimeout(resolve, ms)));
        let buffer = '';
        let inflight = false;
        let closed = false;

        async function pump() {
            if (inflight || closed || !buffer) return;
            inflight = true;
            try {
                while (buffer && !closed) {
                    const chunk = buffer.slice(0, MAX_INPUT_CHUNK);
                    buffer = buffer.slice(chunk.length);
                    const result = await send(chunk);
                    if (result?.retryAfterMs) {
                        buffer = chunk + buffer;
                        await wait(Math.min(result.retryAfterMs, 5000));
                    } else if (result?.stop) {
                        buffer = '';
                        return;
                    }
                }
            } finally {
                inflight = false;
            }
        }

        return {
            push(data) {
                if (closed || typeof data !== 'string' || !data) return false;
                if (buffer.length + data.length > MAX_PENDING_INPUT) return false;
                buffer += data;
                pump();
                return true;
            },
            close() {
                closed = true;
                buffer = '';
            },
            pending() {
                return buffer.length + (inflight ? 1 : 0);
            },
            flushed() {
                return !inflight && !buffer;
            },
        };
    }

    function formatRemaining(milliseconds) {
        const total = Math.max(0, Math.floor(milliseconds / 1000));
        const hours = Math.floor(total / 3600);
        const minutes = Math.floor((total % 3600) / 60);
        if (hours > 0) return `${hours}h ${String(minutes).padStart(2, '0')}m`;
        if (minutes > 0) return `${minutes}m`;
        return `${total}s`;
    }

    function readToken(hash) {
        const raw = String(hash || '').replace(/^#/, '').replace(/^t=/, '');
        try {
            const token = decodeURIComponent(raw).trim();
            return /^[A-Za-z0-9_-]{16,128}$/.test(token) ? token : null;
        } catch {
            return null;
        }
    }

    function pickLanguage(i18n, storage, navigatorObject) {
        if (!i18n) return;
        try {
            if (storage?.getItem('language')) return;
        } catch {
            // Storage can be unavailable in privacy modes.
        }
        const supported = new Set(i18n.getLanguages().map(language => language.code));
        for (const candidate of navigatorObject?.languages || [navigatorObject?.language]) {
            const code = String(candidate || '').slice(0, 2).toLowerCase();
            if (supported.has(code)) {
                i18n.currentLang = code;
                return;
            }
        }
    }

    function boot(win) {
        const doc = win.document;
        const i18n = win.i18n;
        const t = key => (i18n ? i18n.t(key) : key);
        const $ = id => doc.getElementById(id);
        const appRoot = doc.querySelector('meta[name="app-root"]')?.content || '';
        const api = path => `${appRoot}${path}`;

        pickLanguage(i18n, win.localStorage, win.navigator);

        const els = {
            body: doc.body,
            title: $('svTitle'),
            owner: $('svOwner'),
            liveLabel: $('svLiveLabel'),
            mode: $('svMode'),
            modeLabel: $('svModeLabel'),
            viewers: $('svViewers'),
            viewersLabel: $('svViewersLabel'),
            expires: $('svExpires'),
            expiresLabel: $('svExpiresLabel'),
            typingNotice: $('svTypingNotice'),
            banner: $('svBanner'),
            join: $('svJoin'),
            joinForm: $('svJoinForm'),
            joinBtn: $('svJoinBtn'),
            name: $('svName'),
            waiting: $('svWaiting'),
            ended: $('svEnded'),
            endedTitle: $('svEndedTitle'),
            endedIcon: $('svEndedIcon'),
            endedMessage: $('svEndedMessage'),
            rejoin: $('svRejoin'),
            frame: $('svFrame'),
            terminal: $('svTerminal'),
            pointerLayer: $('svPointerLayer'),
            pointButton: $('svPoint'),
            pointerHint: $('svPointerHint'),
            chatToggle: $('svChatToggle'),
            chatBadge: $('svChatBadge'),
            chat: $('svChat'),
            chatClose: $('svChatClose'),
            chatList: $('svChatList'),
            chatEmpty: $('svChatEmpty'),
            chatForm: $('svChatForm'),
            chatInput: $('svChatInput'),
            peek: $('svChatPeek'),
            peekName: $('svChatPeekName'),
            peekText: $('svChatPeekText'),
        };
        const collab = win.WebSSHShareCollab;
        const chatLog = collab.createChatLog();

        const state = {
            token: readToken(win.location.hash),
            ticket: null,
            name: '',
            mode: 'view',
            viewers: 0,
            cols: 80,
            rows: 24,
            lastEventId: null,
            deadline: null,
            heartbeatMs: 15000,
            retry: 0,
            controller: null,
            finished: false,
            autoFit: true,
            fontSize: 14,
            rejoinAttempted: false,
            viewerId: null,
            chatEnabled: false,
            admitted: false,
            chatOpen: false,
            unread: 0,
            pointing: false,
        };

        const term = new win.Terminal({
            cols: state.cols,
            rows: state.rows,
            fontSize: state.fontSize,
            fontFamily: '"JetBrains Mono", "IBM Plex Mono", "Cascadia Code", "SFMono-Regular", Consolas, monospace',
            cursorBlink: false,
            disableStdin: true,
            scrollback: 5000,
            allowProposedApi: false,
            theme: {
                background: '#0d1117',
                foreground: '#e6edf3',
                cursor: '#7ee2b8',
                cursorAccent: '#0d1117',
                selectionBackground: 'rgba(126, 226, 184, 0.28)',
                black: '#484f58', red: '#ff7b72', green: '#7ee2b8', yellow: '#e3b341',
                blue: '#79c0ff', magenta: '#d2a8ff', cyan: '#56d4dd', white: '#e6edf3',
                brightBlack: '#6e7681', brightRed: '#ffa198', brightGreen: '#a5f3cf',
                brightYellow: '#f2cc60', brightBlue: '#a5d6ff', brightMagenta: '#e2c5ff',
                brightCyan: '#88e4ea', brightWhite: '#ffffff',
            },
        });
        term.open(els.terminal);

        // ---------------------------------------------------------------
        // Presentation helpers
        // ---------------------------------------------------------------
        function setState(name) {
            els.body.dataset.state = name;
        }

        function show(element, visible) {
            if (!element) return;
            element.hidden = !visible;
        }

        function setLive(kind) {
            els.body.dataset.connection = kind;
            const key = kind === 'live' ? 'share.viewer.live' : 'share.viewer.connecting';
            els.liveLabel.dataset.i18n = key;
            els.liveLabel.textContent = t(key);
            show(els.banner, kind === 'reconnecting');
        }

        function setMode(mode) {
            state.mode = mode === 'control' ? 'control' : 'view';
            const control = state.mode === 'control';
            els.mode.dataset.mode = state.mode;
            els.mode.querySelector('.material-icons').textContent = control ? 'keyboard' : 'visibility';
            els.modeLabel.dataset.i18n = control ? 'share.viewer.canType' : 'share.viewer.viewOnly';
            els.modeLabel.textContent = t(els.modeLabel.dataset.i18n);
            show(els.mode, true);
            show(els.typingNotice, control);
            term.options.disableStdin = !control;
            term.options.cursorBlink = control;
            els.body.classList.toggle('sv-interactive', control);
        }

        function setViewers(count) {
            state.viewers = Math.max(0, Number(count) || 0);
            els.viewersLabel.textContent = t('share.viewer.watching').replace('{count}', String(state.viewers));
            show(els.viewers, state.viewers > 0);
        }

        function applyViewer(viewer) {
            if (!viewer) return;
            state.viewerId = viewer.viewer_id || state.viewerId;
            state.chatEnabled = viewer.chat_enabled === true;
            if (viewer.status === 'active' && Array.isArray(viewer.chat)) {
                chatLog.replace(viewer.chat);
                renderChat();
            }
            els.title.textContent = viewer.title || 'Shared terminal';
            doc.title = `${viewer.title || 'Shared terminal'} · WebSSH`;
            if (viewer.owner) {
                els.owner.textContent = t('share.viewer.sharedBy').replace('{owner}', viewer.owner);
                show(els.owner, true);
            }
            if (Number.isFinite(viewer.expires_in)) {
                state.deadline = Date.now() + viewer.expires_in * 1000;
                tickCountdown();
            }
            if (Number.isFinite(viewer.heartbeat)) {
                state.heartbeatMs = viewer.heartbeat * 1000;
            }
            setMode(viewer.mode);
            setViewers(viewer.viewers);
            if (viewer.cols && viewer.rows) resizeTerminal(viewer.cols, viewer.rows);
        }

        function tickCountdown() {
            if (!state.deadline) return;
            const remaining = state.deadline - Date.now();
            els.expiresLabel.textContent = t('share.viewer.expiresIn').replace('{time}', formatRemaining(remaining));
            show(els.expires, true);
            els.expires.classList.toggle('sv-chip-warn', remaining < 5 * 60 * 1000);
        }
        win.setInterval(tickCountdown, 1000);

        // ---------------------------------------------------------------
        // Terminal geometry
        // ---------------------------------------------------------------
        function resizeTerminal(cols, rows) {
            cols = Math.max(2, Math.min(1000, Number(cols) || 80));
            rows = Math.max(1, Math.min(500, Number(rows) || 24));
            state.cols = cols;
            state.rows = rows;
            if (term.cols !== cols || term.rows !== rows) term.resize(cols, rows);
            scheduleFit();
        }

        let fitFrame = null;
        function scheduleFit() {
            if (fitFrame) return;
            fitFrame = win.requestAnimationFrame(() => {
                fitFrame = null;
                fit();
            });
        }

        function fit() {
            if (!state.autoFit) return;
            const screen = els.terminal.querySelector('.xterm-screen');
            if (!screen) return;
            const box = els.terminal.getBoundingClientRect();
            const width = screen.offsetWidth;
            const height = screen.offsetHeight;
            if (!width || !height || !box.width || !box.height) return;
            const current = term.options.fontSize;
            const scale = Math.min(box.width / width, box.height / height);
            const next = Math.max(7, Math.min(22, Math.floor(current * scale * 2) / 2));
            if (Math.abs(next - current) >= 0.5) {
                term.options.fontSize = next;
                state.fontSize = next;
                // Character cells do not scale perfectly linearly; settle once more.
                win.requestAnimationFrame(() => {
                    const settled = els.terminal.querySelector('.xterm-screen');
                    if (settled && (settled.offsetWidth > box.width || settled.offsetHeight > box.height)) {
                        term.options.fontSize = Math.max(7, term.options.fontSize - 0.5);
                        state.fontSize = term.options.fontSize;
                    }
                });
            }
        }

        function zoom(delta) {
            state.autoFit = false;
            $('svFit').setAttribute('aria-pressed', 'false');
            state.fontSize = Math.max(7, Math.min(28, term.options.fontSize + delta));
            term.options.fontSize = state.fontSize;
        }

        $('svZoomIn').addEventListener('click', () => zoom(1));
        $('svZoomOut').addEventListener('click', () => zoom(-1));
        $('svFit').addEventListener('click', () => {
            state.autoFit = true;
            $('svFit').setAttribute('aria-pressed', 'true');
            fit();
        });
        $('svFullscreen').addEventListener('click', () => {
            if (doc.fullscreenElement) {
                doc.exitFullscreen?.();
            } else {
                doc.documentElement.requestFullscreen?.().catch(() => {});
            }
        });
        if (typeof win.ResizeObserver === 'function') {
            new win.ResizeObserver(scheduleFit).observe(els.terminal);
        } else {
            win.addEventListener('resize', scheduleFit);
        }

        // ---------------------------------------------------------------
        // Chat and pointers
        // ---------------------------------------------------------------
        const chatLabels = () => ({
            you: t('share.viewer.chatYou'),
            owner: t('share.viewer.chatOwner'),
        });

        function syncCollab() {
            const available = state.chatEnabled && state.admitted && !state.finished;
            show(els.chatToggle, available);
            show(els.pointButton, available);
            if (!available) {
                openChat(false);
                setPointing(false);
            }
        }

        function renderChat() {
            const messages = chatLog.list();
            els.chatList.replaceChildren(...messages.map(message => collab.renderMessage(doc, message, {
                self: message.sender === state.viewerId,
                labels: chatLabels(),
                locale: i18n?.getLanguage?.(),
            })));
            show(els.chatEmpty, messages.length === 0);
            els.chatList.scrollTop = els.chatList.scrollHeight;
        }

        function setUnread(count) {
            state.unread = Math.max(0, count);
            els.chatBadge.textContent = state.unread > 9 ? '9+' : String(state.unread);
            show(els.chatBadge, state.unread > 0);
        }

        function openChat(open) {
            state.chatOpen = Boolean(open);
            show(els.chat, state.chatOpen);
            els.chatToggle.setAttribute('aria-expanded', String(state.chatOpen));
            els.body.classList.toggle('sv-chat-open', state.chatOpen);
            if (state.chatOpen) {
                setUnread(0);
                show(els.peek, false);
                els.chatList.scrollTop = els.chatList.scrollHeight;
                win.setTimeout(() => els.chatInput.focus(), 30);
            }
            scheduleFit();
        }

        let peekTimer = null;
        function peek(message) {
            els.peekName.textContent = message.role === 'owner'
                ? `${message.name} · ${t('share.viewer.chatOwner')}`
                : message.name;
            els.peekText.textContent = message.text;
            show(els.peek, true);
            win.clearTimeout(peekTimer);
            peekTimer = win.setTimeout(() => show(els.peek, false), 4500);
        }

        function receiveChat(message) {
            if (!chatLog.add(message)) return;
            renderChat();
            if (!state.chatOpen && message.sender !== state.viewerId) {
                setUnread(state.unread + 1);
                peek(message);
            }
        }

        function flagComposeError() {
            els.chatForm.classList.remove('is-error');
            void els.chatForm.offsetWidth;
            els.chatForm.classList.add('is-error');
            els.chatInput.title = t('share.viewer.chatFailed');
            win.setTimeout(() => els.chatForm.classList.remove('is-error'), 1200);
        }

        async function sendChat(text) {
            if (!state.ticket || !text) return;
            try {
                const result = await postJson('/api/share-view/chat', { ticket: state.ticket, text });
                if (!result.ok) {
                    if (result.status === 410) finish(result.payload.code || 'session_closed');
                    else flagComposeError();
                    return;
                }
                els.chatInput.value = '';
                els.chatInput.title = '';
                receiveChat(result.payload.message);
            } catch {
                flagComposeError();
            }
        }

        function setPointing(on) {
            state.pointing = Boolean(on) && !state.finished;
            els.pointButton.setAttribute('aria-pressed', String(state.pointing));
            els.body.classList.toggle('sv-pointing', state.pointing);
            show(els.pointerHint, state.pointing);
        }

        function screenRect() {
            return els.terminal.querySelector('.xterm-screen')?.getBoundingClientRect() || null;
        }

        function placePointer(pointer, self = false) {
            const rect = screenRect();
            const box = collab.cellBox(rect, collab.terminalGrid(term), pointer.col, pointer.row);
            if (!rect || !box) return;
            const layer = els.pointerLayer.getBoundingClientRect();
            collab.showPointer(doc, els.pointerLayer, {
                ...box,
                left: box.left + rect.left - layer.left,
                top: box.top + rect.top - layer.top,
            }, {
                name: self ? t('share.viewer.chatYou') : pointer.name,
                role: pointer.role,
                self,
            });
        }

        els.terminal.addEventListener('pointerdown', event => {
            if (!state.pointing) return;
            event.preventDefault();
            event.stopPropagation();
            const cell = collab.cellFromPoint(
                screenRect(), collab.terminalGrid(term), event.clientX, event.clientY,
            );
            if (!cell || !state.ticket) return;
            placePointer({ ...cell, role: 'guest' }, true);
            postJson('/api/share-view/pointer', { ticket: state.ticket, ...cell }).catch(() => {});
        }, true);

        win.addEventListener('keydown', event => {
            if (event.key === 'Escape' && state.pointing) {
                event.preventDefault();
                event.stopPropagation();
                setPointing(false);
            }
        }, true);

        els.pointButton.addEventListener('click', () => setPointing(!state.pointing));
        els.chatToggle.addEventListener('click', () => openChat(!state.chatOpen));
        els.chatClose.addEventListener('click', () => openChat(false));
        els.peek.addEventListener('click', () => openChat(true));
        els.chatForm.addEventListener('submit', event => {
            event.preventDefault();
            sendChat(els.chatInput.value.trim().slice(0, 500));
        });

        // ---------------------------------------------------------------
        // Seat storage
        // ---------------------------------------------------------------
        function loadSeat() {
            try {
                const seat = JSON.parse(win.sessionStorage.getItem(TICKET_STORAGE_KEY) || 'null');
                return seat?.token === state.token ? seat.ticket : null;
            } catch {
                return null;
            }
        }

        function saveSeat(ticket) {
            try {
                if (ticket) {
                    win.sessionStorage.setItem(TICKET_STORAGE_KEY, JSON.stringify({ token: state.token, ticket }));
                } else {
                    win.sessionStorage.removeItem(TICKET_STORAGE_KEY);
                }
            } catch {
                // A reload simply takes a new seat when storage is unavailable.
            }
        }

        // ---------------------------------------------------------------
        // Network
        // ---------------------------------------------------------------
        async function postJson(path, body, extra = {}) {
            const response = await win.fetch(api(path), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
                body: JSON.stringify(body),
                cache: 'no-store',
                credentials: 'same-origin',
                ...extra,
            });
            let payload = {};
            try {
                payload = await response.json();
            } catch {
                payload = {};
            }
            return { status: response.status, ok: response.ok, payload };
        }

        async function join({ name, ticket } = {}) {
            setState('joining');
            els.joinBtn.disabled = true;
            els.joinBtn.querySelector('.sv-btn-label').textContent = t('share.viewer.joining');
            try {
                const body = { token: state.token, name: name || '' };
                if (ticket) body.ticket = ticket;
                const result = await postJson('/api/share-view/join', body);
                if (!result.ok) {
                    finish(result.payload.code || 'unknown');
                    return;
                }
                state.ticket = result.payload.ticket;
                state.lastEventId = null;
                state.rejoinAttempted = false;
                saveSeat(state.ticket);
                applyViewer(result.payload.viewer);
                show(els.join, false);
                if (result.payload.viewer?.status === 'pending') showWaiting();
                connect();
            } catch {
                finish('unknown');
            } finally {
                els.joinBtn.disabled = false;
                els.joinBtn.querySelector('.sv-btn-label').textContent = t('share.viewer.join');
            }
        }

        function showWaiting() {
            setState('waiting');
            show(els.waiting, true);
            state.admitted = false;
            syncCollab();
        }

        function scheduleReconnect() {
            if (state.finished) return;
            setLive('reconnecting');
            const delay = Math.min(15000, 750 * (2 ** Math.min(state.retry, 5)));
            state.retry += 1;
            win.setTimeout(connect, delay + Math.random() * 300);
        }

        async function connect() {
            if (state.finished || !state.ticket) return;
            if (state.retry === 0) setLive('connecting');
            const controller = new win.AbortController();
            state.controller = controller;
            let watchdog = null;
            const armWatchdog = () => {
                win.clearTimeout(watchdog);
                watchdog = win.setTimeout(() => controller.abort(), state.heartbeatMs * 2.5);
            };
            try {
                const body = { ticket: state.ticket };
                if (state.lastEventId !== null) body.last_event_id = state.lastEventId;
                armWatchdog();
                const response = await win.fetch(api('/api/share-view/stream'), {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', Accept: 'text/event-stream' },
                    body: JSON.stringify(body),
                    cache: 'no-store',
                    credentials: 'same-origin',
                    signal: controller.signal,
                });
                if (!response.ok) {
                    win.clearTimeout(watchdog);
                    let code = 'unknown';
                    try {
                        code = (await response.json()).code || code;
                    } catch {
                        // Non-JSON proxy errors are retried like transport errors.
                    }
                    handleStreamRefusal(response.status, code);
                    return;
                }
                const parser = createEventStreamParser(handleEvent);
                const reader = response.body.getReader();
                const decoder = new win.TextDecoder();
                for (;;) {
                    const { value, done } = await reader.read();
                    if (done) break;
                    armWatchdog();
                    parser.push(decoder.decode(value, { stream: true }));
                    if (state.finished) {
                        controller.abort();
                        break;
                    }
                }
            } catch {
                // Aborted or broken transports fall through to reconnect.
            } finally {
                win.clearTimeout(watchdog);
            }
            if (!state.finished && state.controller === controller) scheduleReconnect();
        }

        function handleStreamRefusal(status, code) {
            if (status === 404 && !state.rejoinAttempted && state.token) {
                // The seat expired while we were away; take a fresh one.
                state.rejoinAttempted = true;
                saveSeat(null);
                join({ name: state.name });
                return;
            }
            if (status === 503 || status === 429 || status >= 500) {
                scheduleReconnect();
                return;
            }
            finish(code);
        }

        function handleEvent({ event, id, data }) {
            let payload;
            try {
                payload = JSON.parse(data);
            } catch {
                return;
            }
            if (id !== null) state.lastEventId = id;
            switch (event) {
            case 'hello':
                applyViewer(payload);
                if (payload.status === 'pending') showWaiting();
                break;
            case 'pending':
                showWaiting();
                break;
            case 'reset':
                show(els.waiting, false);
                term.reset();
                resizeTerminal(payload.cols, payload.rows);
                if (payload.data) term.write(payload.data);
                setMode(payload.mode);
                setViewers(payload.viewers);
                if (Array.isArray(payload.chat)) {
                    chatLog.replace(payload.chat);
                    renderChat();
                }
                goLive();
                break;
            case 'chat':
                receiveChat(payload);
                break;
            case 'pointer':
                placePointer(payload);
                break;
            case 'output':
                term.write(payload.data);
                goLive();
                break;
            case 'resize':
                resizeTerminal(payload.cols, payload.rows);
                break;
            case 'mode':
                setMode(payload.mode);
                break;
            case 'presence':
                setViewers(payload.viewers);
                break;
            case 'state':
                setMode(payload.mode);
                setViewers(payload.viewers);
                resizeTerminal(payload.cols, payload.rows);
                goLive();
                break;
            case 'end':
                finish(payload.reason);
                break;
            default:
                break;
            }
        }

        function goLive() {
            if (state.finished) return;
            state.retry = 0;
            setState('live');
            setLive('live');
            if (!state.admitted) {
                state.admitted = true;
                syncCollab();
            }
        }

        const input = createInputQueue(async chunk => {
            if (!state.ticket || state.finished) return { stop: true };
            try {
                const result = await postJson('/api/share-view/input', { ticket: state.ticket, data: chunk });
                if (result.ok) return {};
                if (result.status === 429) return { retryAfterMs: result.payload.retry_after_ms || 250 };
                if (result.payload.code === 'view_only') {
                    setMode('view');
                    return { stop: true };
                }
                if (result.status === 410) {
                    finish(result.payload.code || 'session_closed');
                }
                return { stop: true };
            } catch {
                return { retryAfterMs: 1000 };
            }
        });

        term.onData(data => {
            if (state.mode === 'control' && !state.finished) input.push(data);
        });

        function finish(reason) {
            if (state.finished && reason !== 'left') return;
            state.finished = true;
            input.close();
            state.controller?.abort();
            if (!REJOINABLE.has(reason)) saveSeat(null);
            show(els.banner, false);
            show(els.waiting, false);
            show(els.join, false);
            const unavailable = UNAVAILABLE.has(reason);
            els.endedTitle.dataset.i18n = unavailable ? 'share.viewer.unavailableTitle' : 'share.viewer.endedTitle';
            els.endedTitle.textContent = t(els.endedTitle.dataset.i18n);
            els.endedIcon.textContent = reason === 'left' ? 'waving_hand'
                : reason === 'expired' ? 'timer_off'
                    : unavailable ? 'link_off' : 'power_settings_new';
            els.endedMessage.dataset.i18n = reasonKey(reason);
            els.endedMessage.textContent = t(reasonKey(reason));
            show(els.rejoin, REJOINABLE.has(reason) && Boolean(state.token));
            show(els.ended, true);
            setState('ended');
            els.body.dataset.connection = 'ended';
            term.options.disableStdin = true;
            show(els.typingNotice, false);
            show(els.expires, false);
            show(els.peek, false);
            state.admitted = false;
            syncCollab();
        }

        $('svLeave').addEventListener('click', () => {
            const ticket = state.ticket;
            if (ticket) {
                postJson('/api/share-view/leave', { ticket }, { keepalive: true }).catch(() => {});
            }
            saveSeat(null);
            state.ticket = null;
            finish('left');
        });

        els.rejoin.addEventListener('click', () => {
            state.finished = false;
            state.retry = 0;
            show(els.ended, false);
            term.reset();
            chatLog.replace([]);
            renderChat();
            setUnread(0);
            join({ name: state.name });
        });

        els.joinForm.addEventListener('submit', event => {
            event.preventDefault();
            state.name = els.name.value.trim().slice(0, 32);
            try {
                if (state.name) win.localStorage.setItem(NAME_STORAGE_KEY, state.name);
            } catch {
                // Remembering the name is a convenience only.
            }
            join({ name: state.name });
        });

        // ---------------------------------------------------------------
        // Start
        // ---------------------------------------------------------------
        if (!state.token) {
            finish('no_link');
            return;
        }
        try {
            state.name = win.localStorage.getItem(NAME_STORAGE_KEY) || '';
            els.name.value = state.name;
        } catch {
            state.name = '';
        }
        const seat = loadSeat();
        if (seat) {
            join({ name: state.name, ticket: seat });
        } else {
            setState('join');
            show(els.join, true);
            win.setTimeout(() => els.name.focus(), 50);
        }
    }

    return {
        REASON_KEYS,
        boot,
        createEventStreamParser,
        createInputQueue,
        formatRemaining,
        pickLanguage,
        readToken,
        reasonKey,
    };
});
