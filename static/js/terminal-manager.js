const TerminalManager = {
    terminals: {},
    fitAddons: {},
    searchAddons: {},
    terminalReady: {},
    pendingOutput: {},
    pendingOutputSizes: {},
    sessionTerminals: {},
    transcripts: {},
    transcriptSizes: {},
    sequencedOutput: {},
    sequencedOutputSizes: {},
    lastOutputSequences: {},
    syncedSizes: {},
    scrollbarDisposers: {},
    compositionDisposers: {},
    clipboardDisposers: {},
    terminalWriteCallbacks: {},
    osc52ClipboardAllowed: {},

    isVirtualKeyboardVisible(visualViewportHeight, layoutViewportHeight) {
        if (visualViewportHeight <= 0 || layoutViewportHeight <= 0) {
            return false;
        }
        return (visualViewportHeight / layoutViewportHeight) < 0.75;
    },
    maxTranscriptSize: 200000,
    maxPendingOutputSize: 200000,

    getCssVar(name, fallback = '') {
        return getComputedStyle(document.body).getPropertyValue(name).trim() || fallback;
    },

    isMacPlatform() {
        const platform = navigator.userAgentData?.platform || navigator.platform || navigator.userAgent || '';
        return /mac|iphone|ipad|ipod/i.test(platform);
    },

    isAndroidPlatform() {
        const platform = navigator.userAgentData?.platform || '';
        return /android/i.test(`${platform} ${navigator.userAgent || ''}`);
    },

    setupAndroidCompositionGuard(terminal, isAndroid = this.isAndroidPlatform()) {
        const textarea = terminal?.textarea;
        if (!isAndroid || !textarea?.addEventListener || terminal.options?.screenReaderMode) {
            return () => {};
        }

        const resetStaleInput = () => {
            // Some Android IMEs replace xterm's accumulated helper value when a
            // composition starts. Starting from that stale offset truncates the
            // same number of characters from the committed terminal input.
            textarea.value = '';
            textarea.setSelectionRange?.(0, 0);
        };

        // Capture runs before xterm records the composition's start offset.
        textarea.addEventListener('compositionstart', resetStaleInput, true);
        return () => {
            textarea.removeEventListener('compositionstart', resetStaleInput, true);
        };
    },

    decodeOsc52Clipboard(data, maxBytes = 1024 * 1024) {
        if (typeof data !== 'string') return null;
        const separator = data.indexOf(';');
        if (separator < 0) return null;

        const selection = data.slice(0, separator);
        if (selection && (!/^[cps0-7]+$/.test(selection) || !selection.includes('c'))) {
            return null;
        }

        const encoded = data.slice(separator + 1);
        if (
            !encoded
            || encoded === '?'
            || encoded.length > Math.ceil(maxBytes / 3) * 4
            || !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)
        ) {
            return null;
        }

        const remainder = encoded.length % 4;
        if (remainder === 1) return null;

        try {
            const padded = encoded + '='.repeat((4 - remainder) % 4);
            const binary = atob(padded);
            if (binary.length > maxBytes) return null;
            const bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
            return new TextDecoder('utf-8', {fatal: true}).decode(bytes);
        } catch {
            return null;
        }
    },

    registerOsc52ClipboardHandler(terminal) {
        if (!terminal?.parser?.registerOscHandler) return null;
        let failureReported = false;
        let pendingRequest = null;

        const translation = (key, fallback) => {
            const value = window.i18n?.t?.(key);
            return value && value !== key ? value : fallback;
        };

        const reportFailure = () => {
            if (failureReported) return;
            failureReported = true;
            window.showNotification?.(
                translation(
                    'terminal.remoteClipboardDenied',
                    'Clipboard access denied',
                ),
                'error',
            );
        };

        const oscDisposable = terminal.parser.registerOscHandler(52, data => {
            const text = this.decodeOsc52Clipboard(data);
            if (text === null) return true;

            const clipboard = navigator.clipboard;
            if (!clipboard || typeof clipboard.writeText !== 'function') {
                reportFailure();
                return true;
            }

            if (pendingRequest) {
                pendingRequest.text = text;
                return true;
            }

            const request = {text};
            pendingRequest = request;
            window.showNotification?.({
                message: translation(
                    'terminal.remoteClipboardPrompt',
                    'The remote tmux session wants to copy text to your clipboard.',
                ),
                type: 'info',
                duration: 15000,
                action: {
                    label: translation(
                        'terminal.remoteClipboardApprove',
                        'Copy',
                    ),
                    onClick: () => {
                        if (pendingRequest !== request) return;
                        const requestedText = request.text;
                        pendingRequest = null;
                        try {
                            Promise.resolve(
                                clipboard.writeText(requestedText)
                            ).then(() => {
                                failureReported = false;
                                window.showNotification?.(
                                    translation(
                                        'terminal.remoteClipboardCopied',
                                        'Remote text copied to clipboard',
                                    ),
                                    'success',
                                );
                            }).catch(reportFailure);
                        } catch {
                            reportFailure();
                        }
                    },
                },
                onDismiss: () => {
                    if (pendingRequest === request) pendingRequest = null;
                },
            });
            return true;
        });

        return {
            dispose() {
                pendingRequest = null;
                oscDisposable?.dispose?.();
            },
        };
    },

    activateOsc52ClipboardHandler(terminalKey, expectedTerminal) {
        const terminal = this.terminals[terminalKey];
        if (
            terminal !== expectedTerminal
            || !this.osc52ClipboardAllowed[terminalKey]
            || this.clipboardDisposers[terminalKey]
        ) {
            return;
        }
        const disposable = this.registerOsc52ClipboardHandler(terminal);
        if (disposable) {
            this.clipboardDisposers[terminalKey] = disposable;
        }
    },

    shouldProcessClipboardKeyEvent(event, terminal, isMac) {
        if (event.type !== 'keydown' || event.altKey || event.shiftKey) {
            return true;
        }

        const key = (event.key || '').toLowerCase();
        if (key !== 'c' && key !== 'v') {
            return true;
        }

        if (isMac) {
            return !(event.metaKey && !event.ctrlKey);
        }

        if (!event.ctrlKey || event.metaKey) {
            return true;
        }

        return key === 'c' ? !terminal.hasSelection() : false;
    },

    isCopyShortcut(event, isMac) {
        if (
            event.type !== 'keydown'
            || event.altKey
            || event.shiftKey
            || (event.key || '').toLowerCase() !== 'c'
        ) {
            return false;
        }
        return isMac
            ? event.metaKey && !event.ctrlKey
            : event.ctrlKey && !event.metaKey;
    },

    copySelectionToClipboard(terminal) {
        const selection = terminal?.getSelection?.() || '';
        if (!selection) {
            return Promise.resolve(false);
        }

        const clipboard = navigator.clipboard;
        if (!clipboard || typeof clipboard.writeText !== 'function') {
            return Promise.reject(new Error('Clipboard API unavailable'));
        }

        try {
            return Promise.resolve(clipboard.writeText(selection)).then(() => true);
        } catch (error) {
            return Promise.reject(error);
        }
    },

    handleClipboardKeyEvent(event, terminal, isMac) {
        const shouldProcess = this.shouldProcessClipboardKeyEvent(
            event,
            terminal,
            isMac,
        );
        if (
            !shouldProcess
            && terminal.hasSelection()
            && this.isCopyShortcut(event, isMac)
        ) {
            this.copySelectionToClipboard(terminal).catch(() => {
                window.showNotification?.('Clipboard access denied', 'error');
            });
        }
        return shouldProcess;
    },

    buildTheme() {
        return {
            background: this.getCssVar('--term-background', '#1c2128'),
            foreground: this.getCssVar('--term-foreground', '#e6edf3'),
            cursor: this.getCssVar('--accent-primary', '#58a6ff'),
            cursorAccent: this.getCssVar('--term-background', '#1c2128'),
            selectionBackground: this.getCssVar('--accent-primary-glow', 'rgba(88, 166, 255, 0.4)'),
            black: this.getCssVar('--term-black', '#484848'),
            red: this.getCssVar('--term-red', '#ff6b6b'),
            green: this.getCssVar('--term-green', '#4ec97a'),
            yellow: this.getCssVar('--term-yellow', '#e5c07b'),
            blue: this.getCssVar('--term-blue', '#61afef'),
            magenta: this.getCssVar('--term-magenta', '#c678dd'),
            cyan: this.getCssVar('--term-cyan', '#56b6c2'),
            white: this.getCssVar('--term-white', '#dcdfe4'),
            brightBlack: this.getCssVar('--term-bright-black', '#636363'),
            brightRed: this.getCssVar('--term-bright-red', '#ff8787'),
            brightGreen: this.getCssVar('--term-bright-green', '#7ee0a0'),
            brightYellow: this.getCssVar('--term-bright-yellow', '#ffd68a'),
            brightBlue: this.getCssVar('--term-bright-blue', '#82c8f5'),
            brightMagenta: this.getCssVar('--term-bright-magenta', '#d9a0e8'),
            brightCyan: this.getCssVar('--term-bright-cyan', '#7ccbd4'),
            brightWhite: this.getCssVar('--term-bright-white', '#ffffff')
        };
    },

    getMonoFont() {
        return this.getCssVar('--font-mono', 'monospace');
    },

    getResponsiveFontSize() {
        const width = window.innerWidth;
        if (width < 480) return 12;
        if (width < 768) return 13;
        return 14;
    },

    isMobile() {
        return window.innerWidth < 768 || 'ontouchstart' in window;
    },

    getScrollbackLines() {
        const rawValue = window.BrowserPreferences?.get(
            'terminalScrollback',
            '500',
        ) ?? '500';
        const parsed = Number.parseInt(rawValue, 10);
        if (!Number.isFinite(parsed)) return 500;
        return Math.min(10000, Math.max(50, parsed));
    },

    createTerminal(sessionId, terminalKey = null, options = {}) {
        const key = terminalKey || sessionId;
        const monoFont = this.getMonoFont();
        const theme = this.buildTheme();
        const scrollbackLines = this.getScrollbackLines();
        const terminal = new Terminal({
            cursorBlink: true,
            fontSize: this.getResponsiveFontSize(),
            fontFamily: monoFont || 'monospace',
            theme: theme,
            scrollback: scrollbackLines,
            scrollOnOutput: true,
            scrollOnUserInput: true,
            tabStopWidth: 4,
            allowProposedApi: true
        });

        const isMac = this.isMacPlatform();
        terminal.attachCustomKeyEventHandler(event => (
            this.handleClipboardKeyEvent(event, terminal, isMac)
        ));

        this.osc52ClipboardAllowed[key] = options.allowOsc52Clipboard === true;

        const fitAddon = new FitAddon.FitAddon();
        terminal.loadAddon(fitAddon);

        let searchAddon = null;
        if (typeof SearchAddon !== 'undefined') {
            searchAddon = new SearchAddon.SearchAddon();
            terminal.loadAddon(searchAddon);
        }

        this.terminals[key] = terminal;
        this.fitAddons[key] = fitAddon;
        this.searchAddons[key] = searchAddon;

        if (!this.sessionTerminals[sessionId]) {
            this.sessionTerminals[sessionId] = [];
        }
        if (!this.sessionTerminals[sessionId].includes(key)) {
            this.sessionTerminals[sessionId].push(key);
        }

        return terminal;
    },

    attachTerminal(sessionId, containerId, terminalKey = null) {
        const key = terminalKey || sessionId;
        const terminal = this.terminals[key];
        if (!terminal) {
            console.error('Terminal not found');
            return false;
        }

        const container = document.getElementById(containerId);
        if (!container) {
            console.error('Terminal container not found');
            return false;
        }

        const existingOutput = [...(this.transcripts[sessionId] || [])];
        this.pendingOutput[key] = [];
        this.pendingOutputSizes[key] = 0;
        this.terminalReady[key] = false;
        if (!this.transcripts[sessionId]) {
            this.transcripts[sessionId] = [];
            this.transcriptSizes[sessionId] = 0;
        }

        terminal.open(container);

        this.compositionDisposers[key]?.();
        this.compositionDisposers[key] = this.setupAndroidCompositionGuard(terminal);

        // Add custom scrollbar on the right side of the terminal
        this.setupScrollbar(container, terminal, key);

        requestAnimationFrame(() => {
            requestAnimationFrame(() => {
                this.fitTerminal(sessionId);

                setTimeout(() => {
                    terminal.clear();
                    const pendingOutput = this.pendingOutput[key] || [];
                    this.pendingOutput[key] = [];
                    this.pendingOutputSizes[key] = 0;
                    this.terminalReady[key] = true;

                    const replayOutput = existingOutput.map(data => ({
                        data,
                        onWritten: null,
                    })).concat(pendingOutput);
                    if (replayOutput.length === 0) {
                        this.activateOsc52ClipboardHandler(key, terminal);
                        return;
                    }

                    let remainingWrites = replayOutput.length;
                    replayOutput.forEach(entry => {
                        this.writeOutputToTerminal(key, entry.data, () => {
                            entry.onWritten?.();
                            remainingWrites -= 1;
                            if (remainingWrites === 0) {
                                this.activateOsc52ClipboardHandler(key, terminal);
                            }
                        });
                    });
                }, 50);
            });
        });

        return true;
    },

    writeOutput(sessionId, data, sequence = null, onAccepted = null) {
        const normalizedSequence = Number.isSafeInteger(sequence) && sequence > 0
            ? sequence
            : null;
        if (normalizedSequence !== null) {
            const lastSequence = this.lastOutputSequences[sessionId] || 0;
            if (normalizedSequence <= lastSequence) {
                onAccepted?.();
                return;
            }
            this.lastOutputSequences[sessionId] = normalizedSequence;
            if (!this.sequencedOutput[sessionId]) {
                this.sequencedOutput[sessionId] = [];
                this.sequencedOutputSizes[sessionId] = 0;
            }
            this.sequencedOutput[sessionId].push({
                sequence: normalizedSequence,
                data,
            });
            this.sequencedOutputSizes[sessionId] += data.length;
            while (
                this.sequencedOutputSizes[sessionId] > this.maxTranscriptSize
                && this.sequencedOutput[sessionId].length > 1
            ) {
                const removed = this.sequencedOutput[sessionId].shift();
                this.sequencedOutputSizes[sessionId] -= removed.data.length;
            }
        }
        const terminalKeys = this.sessionTerminals[sessionId] || [];
        this.appendTranscript(sessionId, data);
        if (terminalKeys.length === 0) {
            console.error('Terminal not found for output');
            onAccepted?.();
            return;
        }

        let remainingTerminals = terminalKeys.length;
        const terminalAccepted = () => {
            remainingTerminals -= 1;
            if (remainingTerminals === 0) onAccepted?.();
        };
        terminalKeys.forEach(key => {
            this.writeOutputToTerminal(key, data, terminalAccepted);
        });
    },

    handleSocketOutput(data, acknowledge) {
        let acknowledged = false;
        const acknowledgeOnce = () => {
            if (acknowledged) return;
            acknowledged = true;
            if (typeof acknowledge === 'function') acknowledge();
        };
        try {
            this.writeOutput(
                data.session_id,
                data.data,
                data.sequence,
                acknowledgeOnce,
            );
        } catch (error) {
            acknowledgeOnce();
            throw error;
        }
    },

    writeOutputToTerminal(terminalKey, data, onWritten = null) {
        const terminal = this.terminals[terminalKey];
        if (!terminal) {
            onWritten?.();
            return;
        }

        // Filter out Device Attributes responses (ESC[c sequences only).
        // Bare-pattern regexes were removed because they corrupt legitimate
        // output like "padding:0;color:red" or "cat file".
        data = data.replace(/\x1b\[[?>]?[0-9;]*c/g, '');
        if (!data) {
            onWritten?.();
            return;
        }

        if (this.terminalReady[terminalKey]) {
            if (!this.terminalWriteCallbacks[terminalKey]) {
                this.terminalWriteCallbacks[terminalKey] = new Set();
            }
            let completed = false;
            const complete = () => {
                if (completed) return;
                completed = true;
                this.terminalWriteCallbacks[terminalKey]?.delete(complete);
                onWritten?.();
            };
            this.terminalWriteCallbacks[terminalKey].add(complete);
            try {
                this.writeToTerminalWithScroll(terminal, data, complete);
            } catch (error) {
                complete();
                throw error;
            }
        } else {
            if (!this.pendingOutput[terminalKey]) {
                this.pendingOutput[terminalKey] = [];
                this.pendingOutputSizes[terminalKey] = 0;
            }
            this.pendingOutput[terminalKey].push({data, onWritten});
            this.pendingOutputSizes[terminalKey] = (
                this.pendingOutputSizes[terminalKey] || 0
            ) + data.length;
            while (
                this.pendingOutputSizes[terminalKey] > this.maxPendingOutputSize
                && this.pendingOutput[terminalKey].length > 1
            ) {
                const removed = this.pendingOutput[terminalKey].shift();
                this.pendingOutputSizes[terminalKey] -= removed.data.length;
                // The chunk remains in the separately bounded transcript; it
                // is safe to release server capacity without feeding an
                // unbounded pre-attach xterm queue.
                removed.onWritten?.();
            }
        }
    },

    isTerminalAtBottom(terminal) {
        const buffer = terminal.buffer?.active;
        if (!buffer) {
            return true;
        }
        return buffer.viewportY >= buffer.baseY;
    },

    writeToTerminalWithScroll(terminal, data, onWritten = null) {
        const shouldScroll = this.isTerminalAtBottom(terminal);
        terminal.write(data, () => {
            if (shouldScroll) {
                terminal.scrollToBottom();
            }
            onWritten?.();
        });
    },

    appendTranscript(sessionId, data) {
        if (!this.transcripts[sessionId]) {
            this.transcripts[sessionId] = [];
            this.transcriptSizes[sessionId] = 0;
        }

        this.transcripts[sessionId].push(data);
        this.transcriptSizes[sessionId] += data.length;

        while (this.transcriptSizes[sessionId] > this.maxTranscriptSize && this.transcripts[sessionId].length > 0) {
            const removed = this.transcripts[sessionId].shift();
            this.transcriptSizes[sessionId] -= removed.length;
        }
    },

    seedRestoredOutput(sessionId, bufferedOutput, outputSequence = null) {
        const snapshot = typeof bufferedOutput === 'string' ? bufferedOutput : '';
        if (!snapshot) return;

        const watermark = Number.isSafeInteger(outputSequence) && outputSequence >= 0
            ? outputSequence
            : null;
        let liveOutput = this.getTranscript(sessionId);
        if (watermark !== null) {
            const events = (this.sequencedOutput[sessionId] || [])
                .filter(event => event.sequence > watermark);
            liveOutput = events.map(event => event.data).join('');
            this.sequencedOutput[sessionId] = events;
            this.sequencedOutputSizes[sessionId] = liveOutput.length;
            this.lastOutputSequences[sessionId] = Math.max(
                this.lastOutputSequences[sessionId] || 0,
                watermark,
            );
        }

        const merged = `${snapshot}${liveOutput}`;
        const bounded = merged.slice(-this.maxTranscriptSize);
        this.transcripts[sessionId] = bounded ? [bounded] : [];
        this.transcriptSizes[sessionId] = bounded.length;
    },

    getTranscript(sessionId) {
        if (!this.transcripts[sessionId]) {
            return '';
        }
        return this.transcripts[sessionId].join('');
    },

    getCleanTranscript(sessionId) {
        const raw = this.getTranscript(sessionId);
        if (!raw) {
            return '';
        }
        const stripped = this.stripAnsiSequences(raw);
        return this.normalizeControlChars(stripped);
    },

    stripAnsiSequences(text) {
        return text
            .replace(/\x1b\][^\x07]*(\x07|\x1b\\)/g, '')
            .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '')
            .replace(/\x1b[()][0-2]?/g, '')
            .replace(/\x1b[>=]/g, '')
            .replace(/\x1b[0-9A-Za-z]/g, '')
            .replace(/\x07/g, '');
    },

    normalizeControlChars(text) {
        const output = [];
        let lineStart = 0;
        for (let i = 0; i < text.length; i++) {
            const ch = text[i];
            if (ch === '\n') {
                output.push('\n');
                lineStart = output.length;
                continue;
            }
            if (ch === '\r') {
                output.splice(lineStart);
                continue;
            }
            if (ch === '\b') {
                if (output.length > lineStart) {
                    output.pop();
                }
                continue;
            }
            if (ch === '\t') {
                output.push('\t');
                continue;
            }
            if (ch < ' ') {
                continue;
            }
            output.push(ch);
        }
        return output.join('');
    },

    fitTerminal(sessionId) {
        const terminalKeys = this.sessionTerminals[sessionId] || [];
        terminalKeys.forEach(key => {
            const terminal = this.terminals[key];
            const wrapper = terminal?.element?.closest?.('.terminal-wrapper');
            if (wrapper?.classList.contains('unassigned')) {
                return;
            }
            const fitAddon = this.fitAddons[key];
            if (fitAddon) {
                try {
                    fitAddon.fit();
                } catch {
                    console.error('Error fitting terminal');
                }
            }
        });
    },

    hasVisibleTerminal(sessionId) {
        const terminalKeys = this.sessionTerminals[sessionId] || [];
        return terminalKeys.some(key => {
            const terminal = this.terminals[key];
            const wrapper = terminal?.element?.closest?.('.terminal-wrapper');
            return Boolean(terminal && !wrapper?.classList.contains('unassigned'));
        });
    },

    getVisibleTerminalSize(sessionId) {
        const terminalKeys = this.sessionTerminals[sessionId] || [];
        for (const key of terminalKeys) {
            const terminal = this.terminals[key];
            const wrapper = terminal?.element?.closest?.('.terminal-wrapper');
            if (terminal && !wrapper?.classList.contains('unassigned')) {
                return { rows: terminal.rows, cols: terminal.cols };
            }
        }
        return null;
    },

    fitAndSyncVisibleTerminals({
        socket,
        isConnected = () => true,
        force = false,
    } = {}) {
        const synchronized = [];
        Object.keys(this.sessionTerminals).forEach(sessionId => {
            if (!isConnected(sessionId) || !this.hasVisibleTerminal(sessionId)) {
                return;
            }
            this.fitTerminal(sessionId);
            const size = this.getVisibleTerminalSize(sessionId);
            const previous = this.syncedSizes[sessionId];
            if (!size || (
                !force
                && previous?.rows === size.rows
                && previous?.cols === size.cols
            )) {
                return;
            }
            if (!socket?.emit) {
                return;
            }
            socket.emit('ssh_resize', {
                session_id: sessionId,
                rows: size.rows,
                cols: size.cols,
            });
            this.syncedSizes[sessionId] = { rows: size.rows, cols: size.cols };
            synchronized.push({ sessionId, rows: size.rows, cols: size.cols });
        });
        return synchronized;
    },

    clearSyncedSize(sessionId) {
        delete this.syncedSizes[sessionId];
    },

    getTerminalSize(sessionId) {
        const terminalKeys = this.sessionTerminals[sessionId] || [];
        const terminal = terminalKeys.length > 0 ? this.terminals[terminalKeys[0]] : null;
        if (terminal) {
            return {
                rows: terminal.rows,
                cols: terminal.cols
            };
        }
        return null;
    },

    destroyTerminal(sessionId) {
        const terminalKeys = this.sessionTerminals[sessionId] || [];
        terminalKeys.forEach(key => {
            this.destroyTerminalKey(key, sessionId);
        });
        delete this.sessionTerminals[sessionId];
        delete this.transcripts[sessionId];
        delete this.transcriptSizes[sessionId];
        delete this.sequencedOutput[sessionId];
        delete this.sequencedOutputSizes[sessionId];
        delete this.lastOutputSequences[sessionId];
        this.clearSyncedSize(sessionId);
    },

    setupTouchScroll(container, terminal) {
        const surface = terminal.element || container.querySelector?.('.xterm') || container;
        if (!surface?.addEventListener) return () => {};

        let pointerId = null;
        let lastX = 0;
        let lastY = 0;
        let verticalGesture = false;
        let scrollRemainder = 0;

        const shouldForwardWheel = () => {
            const mouseTrackingMode = terminal.modes?.mouseTrackingMode || 'none';
            const activeBufferType = terminal.buffer?.active?.type || 'normal';
            return mouseTrackingMode !== 'none' || activeBufferType === 'alternate';
        };

        const getLineHeight = () => {
            const renderedHeight = Number(
                terminal._core?._renderService?.dimensions?.css?.cell?.height,
            );
            if (Number.isFinite(renderedHeight) && renderedHeight > 0) {
                return renderedHeight;
            }
            const fontSize = Number(terminal.options?.fontSize);
            return Number.isFinite(fontSize) && fontSize > 0
                ? Math.max(8, fontSize * 1.2)
                : 16;
        };

        const reset = event => {
            if (pointerId === null || (
                event?.pointerId !== undefined && event.pointerId !== pointerId
            )) return;
            surface.releasePointerCapture?.(pointerId);
            pointerId = null;
            verticalGesture = false;
            scrollRemainder = 0;
        };

        const pointerDown = event => {
            if (event.pointerType !== 'touch') return;
            pointerId = event.pointerId;
            lastX = event.clientX;
            lastY = event.clientY;
            verticalGesture = false;
            scrollRemainder = 0;
            try {
                surface.setPointerCapture?.(pointerId);
            } catch {
                // Synthetic and older browser pointer events may not be capturable.
            }
        };

        const pointerMove = event => {
            if (pointerId === null || event.pointerId !== pointerId) return;
            const deltaX = event.clientX - lastX;
            const deltaY = lastY - event.clientY;
            lastX = event.clientX;
            lastY = event.clientY;
            if (!verticalGesture) {
                if (Math.abs(deltaY) < 3 || Math.abs(deltaY) <= Math.abs(deltaX)) return;
                verticalGesture = true;
            }

            if (shouldForwardWheel()) {
                // Full-screen applications consume wheel input themselves. Keep the
                // pointer coordinates so tmux/Vim mouse tracking receives the gesture.
                const WheelConstructor = window.WheelEvent || globalThis.WheelEvent;
                if (typeof WheelConstructor !== 'function') return;
                const wheelEvent = new WheelConstructor('wheel', {
                    bubbles: true,
                    cancelable: true,
                    composed: true,
                    deltaMode: 0,
                    deltaX: 0,
                    deltaY,
                    clientX: event.clientX,
                    clientY: event.clientY,
                });
                surface.dispatchEvent(wheelEvent);
            } else {
                // Synthetic wheel events do not perform the browser's native scroll
                // default action, so normal xterm scrollback must move explicitly.
                scrollRemainder += deltaY;
                const lineHeight = getLineHeight();
                const lines = scrollRemainder < 0
                    ? Math.ceil(scrollRemainder / lineHeight)
                    : Math.floor(scrollRemainder / lineHeight);
                if (lines !== 0) {
                    terminal.scrollLines(lines);
                    scrollRemainder -= lines * lineHeight;
                }
            }
            event.preventDefault?.();
        };

        surface.addEventListener('pointerdown', pointerDown);
        surface.addEventListener('pointermove', pointerMove, {passive: false});
        surface.addEventListener('pointerup', reset);
        surface.addEventListener('pointercancel', reset);

        return () => {
            surface.removeEventListener('pointerdown', pointerDown);
            surface.removeEventListener('pointermove', pointerMove, {passive: false});
            surface.removeEventListener('pointerup', reset);
            surface.removeEventListener('pointercancel', reset);
        };
    },

    setupScrollbar(container, terminal, terminalKey) {
        this.scrollbarDisposers[terminalKey]?.();

        // Create a pointer-capable scrollbar overlay on the right side.
        const scrollbar = document.createElement('div');
        scrollbar.className = 'terminal-scrollbar';
        scrollbar.innerHTML = '<div class="terminal-scrollbar-thumb"></div>';
        container.style.position = 'relative';
        container.appendChild(scrollbar);

        const thumb = scrollbar.querySelector('.terminal-scrollbar-thumb');
        let isDragging = false;
        let dragPointerId = null;
        let startY = 0;
        let startScroll = 0;

        const updateScrollbar = () => {
            const buffer = terminal.buffer.active;
            const totalLines = buffer.length;
            const viewportHeight = terminal.rows;
            const scrollPos = buffer.viewportY;
            const maxScroll = totalLines - viewportHeight;

            if (maxScroll <= 0) {
                scrollbar.style.display = 'none';
                return;
            }
            scrollbar.style.display = 'block';

            const trackHeight = scrollbar.clientHeight;
            const thumbHeight = Math.max(30, (viewportHeight / totalLines) * trackHeight);
            const thumbTop = (scrollPos / maxScroll) * (trackHeight - thumbHeight);

            thumb.style.height = `${thumbHeight}px`;
            thumb.style.top = `${thumbTop}px`;
        };

        // Update scrollbar on terminal output and scroll
        const scrollDisposable = terminal.onScroll(() => updateScrollbar());
        const resizeDisposable = terminal.onResize(() => updateScrollbar());

        // Also update periodically for output-driven changes
        const intervalId = setInterval(() => {
            if (!this.terminals[terminalKey]) {
                clearInterval(intervalId);
                return;
            }
            updateScrollbar();
        }, 500);

        // Drag the thumb with mouse, pen, or touch.
        const pointerDown = event => {
            if (event.button !== undefined && event.button !== 0) return;
            isDragging = true;
            dragPointerId = event.pointerId ?? 'mouse';
            startY = event.clientY;
            startScroll = terminal.buffer.active.viewportY;
            thumb.setPointerCapture?.(event.pointerId);
            event.preventDefault?.();
            event.stopPropagation?.();
        };

        const pointerMove = event => {
            if (!isDragging || (
                event.pointerId !== undefined && event.pointerId !== dragPointerId
            )) return;
            const buffer = terminal.buffer.active;
            const totalLines = buffer.length;
            const maxScroll = totalLines - terminal.rows;
            const trackHeight = scrollbar.clientHeight;
            const thumbHeight = Math.max(30, (terminal.rows / totalLines) * trackHeight);
            const usableTrack = Math.max(1, trackHeight - thumbHeight);
            const deltaY = event.clientY - startY;
            const scrollDelta = (deltaY / usableTrack) * maxScroll;
            const newScroll = Math.max(0, Math.min(maxScroll, Math.round(startScroll + scrollDelta)));
            const currentScroll = buffer.viewportY;
            terminal.scrollLines(newScroll - currentScroll);
            event.preventDefault?.();
        };

        const pointerUp = event => {
            if (!isDragging || (
                event?.pointerId !== undefined && event.pointerId !== dragPointerId
            )) return;
            thumb.releasePointerCapture?.(event?.pointerId);
            isDragging = false;
            dragPointerId = null;
        };

        // Tapping or clicking the track jumps to that position.
        const trackPointerDown = event => {
            if (event.target === thumb) return;
            if (event.button !== undefined && event.button !== 0) return;
            const rect = scrollbar.getBoundingClientRect();
            const clickY = event.clientY - rect.top;
            const trackHeight = rect.height;
            const buffer = terminal.buffer.active;
            const maxScroll = Math.max(0, buffer.length - terminal.rows);
            const targetScroll = Math.round((clickY / trackHeight) * maxScroll);
            const currentScroll = buffer.viewportY;
            terminal.scrollLines(targetScroll - currentScroll);
            event.preventDefault?.();
        };

        thumb.addEventListener('pointerdown', pointerDown);
        thumb.addEventListener('pointermove', pointerMove, {passive: false});
        thumb.addEventListener('pointerup', pointerUp);
        thumb.addEventListener('pointercancel', pointerUp);
        scrollbar.addEventListener('pointerdown', trackPointerDown);

        const disposeTouchScroll = this.setupTouchScroll(container, terminal);
        const dispose = () => {
            clearInterval(intervalId);
            scrollDisposable?.dispose?.();
            resizeDisposable?.dispose?.();
            disposeTouchScroll?.();
            thumb.removeEventListener('pointerdown', pointerDown);
            thumb.removeEventListener('pointermove', pointerMove, {passive: false});
            thumb.removeEventListener('pointerup', pointerUp);
            thumb.removeEventListener('pointercancel', pointerUp);
            scrollbar.removeEventListener('pointerdown', trackPointerDown);
            scrollbar.remove?.();
            if (this.scrollbarDisposers[terminalKey] === dispose) {
                delete this.scrollbarDisposers[terminalKey];
            }
        };
        this.scrollbarDisposers[terminalKey] = dispose;

        updateScrollbar();
        return dispose;
    },

    destroyTerminalKey(terminalKey, sessionId) {
        const terminal = this.terminals[terminalKey];
        (this.pendingOutput[terminalKey] || []).forEach(entry => {
            entry.onWritten?.();
        });
        (this.terminalWriteCallbacks[terminalKey] || new Set()).forEach(
            callback => callback()
        );
        this.scrollbarDisposers[terminalKey]?.();
        this.compositionDisposers[terminalKey]?.();
        this.clipboardDisposers[terminalKey]?.dispose?.();
        if (terminal) {
            terminal.dispose();
        }
        delete this.terminals[terminalKey];
        delete this.fitAddons[terminalKey];
        delete this.searchAddons[terminalKey];
        delete this.terminalReady[terminalKey];
        delete this.pendingOutput[terminalKey];
        delete this.pendingOutputSizes[terminalKey];
        delete this.compositionDisposers[terminalKey];
        delete this.clipboardDisposers[terminalKey];
        delete this.terminalWriteCallbacks[terminalKey];
        delete this.osc52ClipboardAllowed[terminalKey];

        if (sessionId && this.sessionTerminals[sessionId]) {
            this.sessionTerminals[sessionId] = this.sessionTerminals[sessionId].filter(key => key !== terminalKey);
        }
    },

    clear(sessionId) {
        const terminal = this.terminals[sessionId];
        if (terminal) {
            terminal.clear();
        }
    },

    setupInputHandler(sessionId, callback) {
        const terminalKeys = this.sessionTerminals[sessionId] || [];
        terminalKeys.forEach(key => {
            this.setupInputHandlerForTerminal(key, callback);
        });
    },

    setupInputHandlerForTerminal(terminalKey, callback) {
        const terminal = this.terminals[terminalKey];
        if (terminal) {
            terminal.onData(callback);
        }
    },

    fitAllTerminals() {
        Object.keys(this.sessionTerminals).forEach(sessionId => {
            this.fitTerminal(sessionId);
        });
    },

    applyThemeToTerminal(sessionId) {
        const terminalKeys = this.sessionTerminals[sessionId] || [];
        const theme = this.buildTheme();
        const font = this.getMonoFont();
        terminalKeys.forEach(key => {
            const terminal = this.terminals[key];
            if (!terminal) {
                return;
            }
            terminal.options.theme = theme;
            terminal.options.fontFamily = font;
            terminal.refresh(0, terminal.rows - 1);
        });
    },

    applyThemeToAll() {
        requestAnimationFrame(() => {
            Object.keys(this.sessionTerminals).forEach(sessionId => {
                this.applyThemeToTerminal(sessionId);
            });
        });
    },

    findNext(sessionId, searchTerm, options = {}) {
        const terminalKeys = this.sessionTerminals[sessionId] || [];
        if (terminalKeys.length === 0) return false;

        const searchAddon = this.searchAddons[terminalKeys[0]];
        if (!searchAddon) return false;

        return searchAddon.findNext(searchTerm, {
            caseSensitive: options.caseSensitive || false,
            wholeWord: options.wholeWord || false,
            regex: options.regex || false,
            incremental: options.incremental !== false
        });
    },

    findPrevious(sessionId, searchTerm, options = {}) {
        const terminalKeys = this.sessionTerminals[sessionId] || [];
        if (terminalKeys.length === 0) return false;

        const searchAddon = this.searchAddons[terminalKeys[0]];
        if (!searchAddon) return false;

        return searchAddon.findPrevious(searchTerm, {
            caseSensitive: options.caseSensitive || false,
            wholeWord: options.wholeWord || false,
            regex: options.regex || false
        });
    },

    clearSearch(sessionId) {
        const terminalKeys = this.sessionTerminals[sessionId] || [];
        if (terminalKeys.length === 0) return;

        const searchAddon = this.searchAddons[terminalKeys[0]];
        if (searchAddon) {
            searchAddon.clearDecorations();
        }
    },

    hasSearchSupport() {
        return typeof SearchAddon !== 'undefined';
    },

    updateFontSize(newSize) {
        Object.values(this.terminals).forEach(terminal => {
            if (terminal) {
                terminal.options.fontSize = newSize;
            }
        });
        this.fitAllTerminals();
    },

    handleOrientationChange() {
        const newFontSize = this.getResponsiveFontSize();
        this.updateFontSize(newFontSize);
        setTimeout(() => {
            this.fitAllTerminals();
        }, 100);
    }
};

window.TerminalManager = TerminalManager;

let resizeTimeout;
window.addEventListener('resize', () => {
    clearTimeout(resizeTimeout);
    resizeTimeout = setTimeout(() => {
        TerminalManager.fitAllTerminals();
    }, 250);
});

window.addEventListener('orientationchange', () => {
    TerminalManager.handleOrientationChange();
});

if (window.visualViewport) {
    let keyboardVisible = false;

    window.visualViewport.addEventListener('resize', () => {
        const currentHeight = window.visualViewport.height;
        const newKeyboardVisible = TerminalManager.isVirtualKeyboardVisible(
            currentHeight,
            window.innerHeight,
        );

        if (newKeyboardVisible !== keyboardVisible) {
            keyboardVisible = newKeyboardVisible;
            const notepadFocused = document.activeElement?.id === 'sessionNotepad';
            document.body.classList.toggle('keyboard-open', keyboardVisible);
            document.body.classList.toggle('notepad-focused', keyboardVisible && notepadFocused);

            clearTimeout(resizeTimeout);
            resizeTimeout = setTimeout(() => {
                TerminalManager.fitAllTerminals();
            }, 100);
        }
    });
}
