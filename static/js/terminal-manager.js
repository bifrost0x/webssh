const TerminalManager = {
    terminals: {},
    fitAddons: {},
    searchAddons: {},
    terminalReady: {},
    pendingOutput: {},
    sessionTerminals: {},
    transcripts: {},
    transcriptSizes: {},
    maxTranscriptSize: 200000,

    getCssVar(name, fallback = '') {
        return getComputedStyle(document.body).getPropertyValue(name).trim() || fallback;
    },

    isMacPlatform() {
        const platform = navigator.userAgentData?.platform || navigator.platform || navigator.userAgent || '';
        return /mac|iphone|ipad|ipod/i.test(platform);
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

    createTerminal(sessionId, terminalKey = null) {
        const key = terminalKey || sessionId;
        const monoFont = this.getMonoFont();
        const theme = this.buildTheme();
        const scrollbackLines = parseInt(localStorage.getItem('terminalScrollback') || '150', 10);
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
            this.shouldProcessClipboardKeyEvent(event, terminal, isMac)
        ));

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
            console.error('Terminal not found:', sessionId);
            return false;
        }

        const container = document.getElementById(containerId);
        if (!container) {
            console.error('Container not found:', containerId);
            return false;
        }

        this.pendingOutput[key] = [];
        this.terminalReady[key] = false;
        if (!this.transcripts[sessionId]) {
            this.transcripts[sessionId] = [];
            this.transcriptSizes[sessionId] = 0;
        }

        terminal.open(container);

        // Add custom scrollbar on the right side of the terminal
        this.setupScrollbar(container, terminal, key);

        requestAnimationFrame(() => {
            requestAnimationFrame(() => {
                this.fitTerminal(sessionId);

                setTimeout(() => {
                    terminal.clear();
                    // Discard any output buffered before the terminal was ready
                    // to prevent stale output from previous sessions appearing
                    this.pendingOutput[key] = [];

                    this.terminalReady[key] = true;
                }, 50);
            });
        });

        return true;
    },

    writeOutput(sessionId, data) {
        const terminalKeys = this.sessionTerminals[sessionId] || [];
        this.appendTranscript(sessionId, data);
        if (terminalKeys.length === 0) {
            console.error('Terminal not found for writeOutput:', sessionId);
            return;
        }

        terminalKeys.forEach(key => {
            this.writeOutputToTerminal(key, data, sessionId);
        });
    },

    writeOutputToTerminal(terminalKey, data, sessionId) {
        const terminal = this.terminals[terminalKey];
        if (!terminal) {
            return;
        }

        // Filter out Device Attributes responses (ESC[c sequences only).
        // Bare-pattern regexes were removed because they corrupt legitimate
        // output like "padding:0;color:red" or "cat file".
        data = data.replace(/\x1b\[[?>]?[0-9;]*c/g, '');

        if (this.terminalReady[terminalKey]) {
            this.writeToTerminalWithScroll(terminal, data);
        } else {
            if (!this.pendingOutput[terminalKey]) {
                this.pendingOutput[terminalKey] = [];
            }
            this.pendingOutput[terminalKey].push(data);
            console.log(`Buffering output for ${sessionId} (terminal not ready yet)`);
        }
    },

    isTerminalAtBottom(terminal) {
        const buffer = terminal.buffer?.active;
        if (!buffer) {
            return true;
        }
        return buffer.viewportY >= buffer.baseY;
    },

    writeToTerminalWithScroll(terminal, data) {
        const shouldScroll = this.isTerminalAtBottom(terminal);
        terminal.write(data, () => {
            if (shouldScroll) {
                terminal.scrollToBottom();
            }
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
            const fitAddon = this.fitAddons[key];
            if (fitAddon) {
                try {
                    fitAddon.fit();
                } catch (e) {
                    console.error('Error fitting terminal:', e);
                }
            }
        });
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
    },

    setupScrollbar(container, terminal, terminalKey) {
        // Create custom scrollbar overlay on the right side
        const scrollbar = document.createElement('div');
        scrollbar.className = 'terminal-scrollbar';
        scrollbar.innerHTML = '<div class="terminal-scrollbar-thumb"></div>';
        container.style.position = 'relative';
        container.appendChild(scrollbar);

        const thumb = scrollbar.querySelector('.terminal-scrollbar-thumb');
        let isDragging = false;
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
        terminal.onScroll(() => updateScrollbar());
        terminal.onResize(() => updateScrollbar());

        // Also update periodically for output-driven changes
        const intervalId = setInterval(() => {
            if (!this.terminals[terminalKey]) {
                clearInterval(intervalId);
                return;
            }
            updateScrollbar();
        }, 500);

        // Drag to scroll
        thumb.addEventListener('mousedown', (e) => {
            isDragging = true;
            startY = e.clientY;
            startScroll = terminal.buffer.active.viewportY;
            e.preventDefault();
        });

        document.addEventListener('mousemove', (e) => {
            if (!isDragging) return;
            const buffer = terminal.buffer.active;
            const totalLines = buffer.length;
            const maxScroll = totalLines - terminal.rows;
            const trackHeight = scrollbar.clientHeight;
            const thumbHeight = Math.max(30, (terminal.rows / totalLines) * trackHeight);
            const deltaY = e.clientY - startY;
            const scrollDelta = (deltaY / (trackHeight - thumbHeight)) * maxScroll;
            const newScroll = Math.max(0, Math.min(maxScroll, Math.round(startScroll + scrollDelta)));
            const currentScroll = buffer.viewportY;
            terminal.scrollLines(newScroll - currentScroll);
        });

        document.addEventListener('mouseup', () => {
            isDragging = false;
        });

        // Click on track to scroll
        scrollbar.addEventListener('click', (e) => {
            if (e.target === thumb) return;
            const rect = scrollbar.getBoundingClientRect();
            const clickY = e.clientY - rect.top;
            const trackHeight = rect.height;
            const buffer = terminal.buffer.active;
            const maxScroll = buffer.length - terminal.rows;
            const targetScroll = Math.round((clickY / trackHeight) * maxScroll);
            const currentScroll = buffer.viewportY;
            terminal.scrollLines(targetScroll - currentScroll);
        });

        updateScrollbar();
    },

    destroyTerminalKey(terminalKey, sessionId) {
        const terminal = this.terminals[terminalKey];
        if (terminal) {
            terminal.dispose();
        }
        delete this.terminals[terminalKey];
        delete this.fitAddons[terminalKey];
        delete this.searchAddons[terminalKey];
        delete this.terminalReady[terminalKey];
        delete this.pendingOutput[terminalKey];

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
        Object.keys(this.terminals).forEach(key => {
            const terminal = this.terminals[key];
            if (terminal) {
                terminal.options.fontSize = newSize;
                const fitAddon = this.fitAddons[key];
                if (fitAddon) {
                    try {
                        fitAddon.fit();
                    } catch (e) {
                        console.error('Error fitting terminal after font change:', e);
                    }
                }
            }
        });
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
    const initialHeight = window.visualViewport.height;
    let keyboardVisible = false;

    window.visualViewport.addEventListener('resize', () => {
        const currentHeight = window.visualViewport.height;
        const heightRatio = currentHeight / initialHeight;

        const newKeyboardVisible = heightRatio < 0.75;

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
