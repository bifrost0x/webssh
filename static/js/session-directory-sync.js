(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root?.document) root.SessionDirectorySync = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    'use strict';

    const inputs = new Map();
    const directoryObservers = new Set();

    function parseOsc7(data) {
        if (typeof data !== 'string' || data.length < 8 || data.length > 8192) return null;
        let url;
        try {
            url = new URL(data);
        } catch {
            return null;
        }
        if (url.protocol !== 'file:' || url.username || url.password
                || url.search || url.hash || url.hostname.length > 255) return null;
        let path;
        try {
            path = decodeURIComponent(url.pathname);
        } catch {
            return null;
        }
        if (!validPath(path)) return null;
        return { host: url.hostname, path };
    }

    function trackTerminal(sessionId, terminal) {
        const state = { dirty: true, version: 0, terminal, pasting: false, submitted: false, submitOutput: false };
        inputs.set(sessionId, state);
        // Readline/ZLE announce the start of an editable prompt with DEC 2004.
        // Return false so xterm still handles the mode itself. An alternate
        // screen and the remote foreground-process check are separate guards.
        const promptDisposable = terminal.parser.registerCsiHandler({ prefix: '?', final: 'h' }, params => {
            if (params.includes(2004) && !state.replayDepth) state.dirty = false;
            return false;
        });
        const inputDisposable = terminal.onData(data => noteInput(sessionId, data));
        // tmux may combine readline's disable/enable into no outer mode change.
        // A submitted line must produce live output before a fresh pane probe
        // may acknowledge it. Status redraws alone do not count as a new line.
        const lineDisposable = terminal.onLineFeed?.(() => {
            if (state.submitted && !state.submitOutput && !state.replayDepth) {
                state.submitOutput = true;
                // A probe started before this output cannot attest to the
                // prompt after it. Require a new snapshot for navigation.
                state.version += 1;
            }
        });
        const oscDisposable = terminal.parser.registerOscHandler?.(7, data => {
            const location = parseOsc7(data);
            if (!location || state.replayDepth
                    || terminal.buffer?.active?.type !== 'normal') return true;
            directoryObservers.forEach(observer => observer({ sessionId, ...location }));
            return true;
        });
        return {
            dispose() {
                promptDisposable?.dispose?.();
                inputDisposable?.dispose?.();
                lineDisposable?.dispose?.();
                oscDisposable?.dispose?.();
                if (inputs.get(sessionId) === state) inputs.delete(sessionId);
            },
        };
    }

    function noteInput(sessionId, data) {
        if (!data) return;
        // xterm emits terminal replies through onData too. tmux queries its
        // foreground/background colours after enabling prompt mode at startup.
        // These exact replies must not count as typing (or invalidate a probe).
        // Keep forwarding them through SSHInput; only input tracking ignores them.
        const reply = /^(?:\x1b\[[?>]?[0-9;]*c|\x1b\](?:10|11|12);rgb:[0-9a-f]{1,4}\/[0-9a-f]{1,4}\/[0-9a-f]{1,4}(?:\x1b\\|\x07))$/i.exec(data);
        if (reply?.[0] === data) return;
        const state = inputs.get(sessionId);
        if (state) {
            state.dirty = true;
            state.version += 1;
            if (data.includes('\x1b[200~')) state.pasting = true;
            if (data.includes('\x1b[201~')) state.pasting = false;
            state.submitted = !state.pasting && ['\r', '\n', '\x03'].includes(data);
            state.submitOutput = false;
        }
    }

    function beginReplay(sessionId) {
        const state = inputs.get(sessionId);
        if (!state) return;
        state.replayDepth = (state.replayDepth || 0) + 1;
        state.dirty = true;
        state.version += 1;
        state.submitted = state.submitOutput = false;
    }

    function endReplay(sessionId) {
        const state = inputs.get(sessionId);
        if (!state) return;
        state.replayDepth = Math.max(0, (state.replayDepth || 0) - 1);
        // An old prompt in the transcript may be followed by unfinished input.
        // Require a subsequent live prompt boundary before sending a command.
        state.dirty = true;
    }

    function canSend(sessionId, directory = null) {
        const state = inputs.get(sessionId);
        if (!state || state.replayDepth) return false;
        if (directory?.tmux === true) {
            if (directory.bracketed_paste === undefined) {
                // Legacy tmux coalesces prompt-mode changes too. Use its live
                // outer mode together with a fresh foreground-shell probe and
                // output after submission, just as for a reported pane mode.
                return Boolean(directory.shell_ready
                    && state.terminal.modes.bracketedPasteMode
                    && (!state.dirty || (state.submitted && state.submitOutput)));
            }
            return Boolean(directory.shell_ready && directory.bracketed_paste === true
                && (!state.dirty || (state.submitted && state.submitOutput)));
        }
        return Boolean(state && !state.dirty
            && state.terminal.buffer.active.type === 'normal'
            && state.terminal.modes.bracketedPasteMode);
    }

    function confirmNavigation(sessionId, version) {
        const state = inputs.get(sessionId);
        // tmux can coalesce readline's disable/enable pair. A confirmed cwd
        // change from our own cd can acknowledge that command, never user input.
        if (state && state.version === version && !state.replayDepth) state.dirty = false;
    }

    function validPath(path) {
        return typeof path === 'string' && path.startsWith('/')
            && new TextEncoder().encode(path).length <= 4096
            && !/[\x00-\x1f\x7f-\x9f]/.test(path);
    }

    function cdCommand(path, shell = 'sh') {
        if (!validPath(path)) return null;
        if (shell === 'fish') {
            return `cd -- '${path.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'\r`;
        }
        return `cd -- '${path.replace(/'/g, `'\\''`)}'\r`;
    }

    function createController(options) {
        const { socket, manager, indicator, input, panel } = options;
        const setTimer = options.setTimeout || setTimeout;
        const clearTimer = options.clearTimeout || clearTimeout;
        const now = options.now || Date.now;
        const inputReady = options.canSend || canSend;
        const inputVersion = options.inputVersion || (id => inputs.get(id)?.version);
        const confirmInput = options.confirmNavigation || confirmNavigation;
        const blocked = reason => options.onNavigationBlocked?.(reason);
        const enabledByDefault = options.enabledByDefault !== false;
        const sessionOverrides = new Map();
        let sessionId = null;
        let visible = false;
        let generation = 0;
        let timer = null;
        let timeout = null;
        let oscFollowTimer = null;
        let pendingOscLocation = null;
        let request = null;
        let directory = null;
        let awaitingChange = null;
        let lastOscAt = 0;
        let lastOscFollowAt = 0;
        const oscFallbackDelay = Math.max(5000, options.oscFallbackDelay || 15000);
        const oscFollowInterval = Math.max(100, options.oscFollowInterval || 300);

        function isEnabled(id) {
            return Boolean(id && (sessionOverrides.has(id)
                ? sessionOverrides.get(id)
                : enabledByDefault));
        }

        function active() {
            return Boolean(sessionId && visible && isEnabled(sessionId)
                && manager.isEmbeddedOpen?.()
                && manager.getPaneSourceId('left') === `sftp-session:${sessionId}`);
        }

        function cancel() {
            generation += 1;
            clearTimer(timer);
            clearTimer(timeout);
            clearTimer(oscFollowTimer);
            timer = timeout = request = null;
            oscFollowTimer = null;
            pendingOscLocation = null;
            awaitingChange = null;
        }

        function render() {
            const enabled = isEnabled(sessionId);
            if (indicator) indicator.hidden = !sessionId;
            if (input) {
                input.checked = enabled;
                input.disabled = !sessionId;
            }
            if (panel?.dataset) panel.dataset.directorySyncEnabled = String(enabled);
        }

        function setEnabled(value) {
            if (!sessionId) return false;
            sessionOverrides.set(sessionId, Boolean(value));
            cancel();
            directory = null;
            render();
            if (isEnabled(sessionId)) poll();
            return true;
        }

        function schedule(delay = 1500) {
            clearTimer(timer);
            const oscAge = now() - lastOscAt;
            if (!awaitingChange && lastOscAt && oscAge < oscFallbackDelay) {
                delay = Math.max(delay, oscFallbackDelay - oscAge);
            }
            if (active()) timer = setTimer(() => poll(), delay);
        }

        function follow(path) {
            const state = manager.panes.left;
            state.autoHomeEligible = false;
            if (state.path !== path) manager.navigatePaneTo('left', path, { directorySync: true });
        }

        function poll(targetPath = null, version = inputVersion(sessionId)) {
            if (!active() || request) return false;
            const token = { generation, sessionId, version, targetPath };
            request = token;
            timeout = setTimer(() => {
                if (request !== token) return;
                request = null;
                if (token.targetPath !== null || token.nextNavigation || awaitingChange) blocked('unavailable');
                awaitingChange = null;
                schedule(10000);
            }, 5000);
            socket.emit('request_session_directory', { session_id: sessionId }, result => {
                if (request !== token || token.generation !== generation || !active()) return;
                clearTimer(timeout);
                request = null;
                if (token.nextNavigation) {
                    // Let an existing read finish before opening the fresh
                    // navigation probe: the server permits one probe at a time.
                    const intent = token.nextNavigation;
                    if (intent.version !== inputVersion(sessionId)) {
                        blocked('prompt');
                        schedule();
                    } else {
                        poll(intent.path, intent.version);
                    }
                    return;
                }
                const next = result?.directory;
                if (!result?.success || !validPath(next?.path)) {
                    if (targetPath !== null || awaitingChange) blocked('unavailable');
                    awaitingChange = null;
                    schedule(10000);
                    return;
                }
                directory = next;
                if (targetPath !== null) {
                    if (!next.shell_ready || !inputReady(sessionId, next)
                            || token.version !== inputVersion(sessionId)
                            || options.hasPendingInput?.(sessionId)) {
                        blocked('prompt');
                        schedule();
                        return;
                    }
                    if (next.path === targetPath) {
                        follow(next.path);
                        schedule();
                        return;
                    }
                    awaitingChange = { previous: next.path, shellId: next.shell_id, polls: 0, version: null };
                    noteInput(sessionId, targetPath);
                    // Deliberately target this SSH session, never broadcast.
                    options.sendInput(sessionId, cdCommand(targetPath, next.shell));
                    awaitingChange.version = inputVersion(sessionId);
                    schedule(350);
                    return;
                }
                if (awaitingChange) {
                    awaitingChange.polls += 1;
                    if (next.tmux === true && (next.bracketed_paste === true || next.bracketed_paste === undefined)
                            && next.shell_ready && next.path !== awaitingChange.previous
                            && next.shell_id === awaitingChange.shellId
                            && awaitingChange.version === inputVersion(sessionId)
                            && !options.hasPendingInput?.(sessionId)) {
                        confirmInput(sessionId, awaitingChange.version);
                    }
                    if (!next.shell_ready || !inputReady(sessionId, next)) {
                        if (awaitingChange.polls >= 6) {
                            awaitingChange = null;
                            blocked('prompt');
                        }
                        schedule(); return;
                    }
                    if (next.path === awaitingChange.previous && awaitingChange.polls < 3) {
                        schedule(500);
                        return;
                    }
                    awaitingChange = null;
                    follow(next.path);
                    schedule();
                    return;
                }
                follow(next.path);
                schedule();
            });
            return true;
        }

        input?.addEventListener?.('change', () => setEnabled(input.checked));

        const applyOscLocation = detail => {
            oscFollowTimer = null;
            pendingOscLocation = null;
            lastOscFollowAt = now();
            directory = { path: detail.path, host: detail.host || '', shell_ready: true };
            if (awaitingChange && detail.path !== awaitingChange.previous) awaitingChange = null;
            follow(detail.path);
            schedule(oscFallbackDelay);
        };

        const directoryListener = detail => {
            if (!detail || detail.sessionId !== sessionId || !active()
                    || !validPath(detail.path)) return;
            // Prompt/location output must not discard an explicit folder click
            // while its fresh probe or command acknowledgement is in flight.
            if ((request && request.targetPath !== null) || request?.nextNavigation || awaitingChange) return;
            generation += 1;
            clearTimer(timer);
            clearTimer(timeout);
            timer = timeout = request = null;
            lastOscAt = now();
            const wait = oscFollowInterval - (lastOscAt - lastOscFollowAt);
            if (wait <= 0) {
                clearTimer(oscFollowTimer);
                applyOscLocation(detail);
                return;
            }
            pendingOscLocation = detail;
            clearTimer(oscFollowTimer);
            oscFollowTimer = setTimer(() => {
                if (pendingOscLocation && active()) applyOscLocation(pendingOscLocation);
            }, wait);
        };
        directoryObservers.add(directoryListener);

        return {
            setContext(id, isVisible) {
                if (id === sessionId && visible === isVisible) {
                    // The embedded source can finish mounting after context selection.
                    if (active() && timer === null && !request) poll();
                    return;
                }
                cancel();
                sessionId = id;
                visible = isVisible;
                directory = null;
                lastOscAt = 0;
                lastOscFollowAt = 0;
                render();
                poll();
            },
            navigate(id, path) {
                if (id !== sessionId || !active()) return false;
                if (!validPath(path)) {
                    return true;
                }
                if (awaitingChange) {
                    blocked('pending');
                    return true;
                }
                const intent = {path, version: inputVersion(sessionId)};
                if (request) {
                    clearTimer(timer);
                    clearTimer(oscFollowTimer);
                    timer = oscFollowTimer = pendingOscLocation = null;
                    request.nextNavigation = intent;
                    return true;
                }
                cancel();
                poll(path, intent.version);
                return true;
            },
            removeSession(id) {
                inputs.delete(id);
                sessionOverrides.delete(id);
                if (id === sessionId) { cancel(); sessionId = null; render(); }
            },
            setEnabled,
            isEnabled,
            getDirectory() { return directory; },
            observe(id, path, host = '') {
                directoryListener({ sessionId: id, path, host });
            },
            dispose() {
                cancel();
                directoryObservers.delete(directoryListener);
            },
        };
    }

    return {
        createController,
        trackTerminal,
        beginReplay,
        endReplay,
        noteInput,
        canSend,
        cdCommand,
        validPath,
        parseOsc7,
    };
}));
