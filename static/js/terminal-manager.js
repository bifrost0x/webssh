// Terminal Manager - Manages xterm.js terminal instances
const TerminalManager = {
    terminals: {},
    fitAddons: {},
    searchAddons: {},  // SearchAddon instances per terminal
    terminalReady: {},  // Track which terminals are fully initialized
    pendingOutput: {},  // Buffer output until terminal is ready
    sessionTerminals: {},
    transcripts: {},
    transcriptSizes: {},
    maxTranscriptSize: 200000, // Keep ~200k chars per session to limit memory

    getCssVar(name, fallback = '') {
        return getComputedStyle(document.body).getPropertyValue(name).trim() || fallback;
    },

    buildTheme() {
        return {
            background: this.getCssVar('--bg-tertiary', '#1c2128'),
            foreground: this.getCssVar('--text-primary', '#e6edf3'),
            cursor: this.getCssVar('--accent-primary', '#58a6ff'),
            selection: this.getCssVar('--accent-primary-glow', 'rgba(88, 166, 255, 0.4)')
        };
    },

    getMonoFont() {
        return this.getCssVar('--font-mono', 'monospace');
    },

    createTerminal(sessionId, terminalKey = null) {
        const key = terminalKey || sessionId;
        // Create new xterm.js Terminal instance
        const monoFont = this.getMonoFont();
        const theme = this.buildTheme();
        const terminal = new Terminal({
            cursorBlink: true,
            fontSize: 14,
            fontFamily: monoFont || 'monospace',
            theme: theme,
            scrollback: 50000,
            scrollOnOutput: true,
            scrollOnUserInput: true,
            tabStopWidth: 4
        });

        // Create fit addon for responsive sizing
        const fitAddon = new FitAddon.FitAddon();
        terminal.loadAddon(fitAddon);

        // Create search addon if available
        let searchAddon = null;
        if (typeof SearchAddon !== 'undefined') {
            searchAddon = new SearchAddon.SearchAddon();
            terminal.loadAddon(searchAddon);
        }

        // Store terminal and addons
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

        // Initialize pending output buffer
        this.pendingOutput[key] = [];
        this.terminalReady[key] = false;
        if (!this.transcripts[sessionId]) {
            this.transcripts[sessionId] = [];
            this.transcriptSizes[sessionId] = 0;
        }

        // Open terminal in container
        terminal.open(container);

        // CRITICAL: Wait for terminal to fully render before marking as ready
        // This prevents xterm.js from rendering placeholder "W" characters
        requestAnimationFrame(() => {
            requestAnimationFrame(() => {
                // Fit the terminal first
                this.fitTerminal(sessionId);

                // Small additional delay to ensure rendering is complete
                setTimeout(() => {
                    // Clear any placeholder render artifacts before first output
                    terminal.clear();

                    // Mark terminal as ready
                    this.terminalReady[key] = true;

                    // Flush any pending output
                    if (this.pendingOutput[key] && this.pendingOutput[key].length > 0) {
                        console.log(`Flushing ${this.pendingOutput[key].length} pending outputs for ${sessionId}`);
                        this.pendingOutput[key].forEach(data => {
                            this.writeToTerminalWithScroll(terminal, data);
                        });
                        this.pendingOutput[key] = [];
                    }
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
            // OSC sequences
            .replace(/\x1b\][^\x07]*(\x07|\x1b\\)/g, '')
            // CSI sequences
            .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '')
            // ESC sequences
            .replace(/\x1b[()][0-2]?/g, '')
            .replace(/\x1b[>=]/g, '')
            .replace(/\x1b[0-9A-Za-z]/g, '')
            // Bells
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
        terminalKeys.forEach(key => {
            const terminal = this.terminals[key];
            if (!terminal) {
                return;
            }
            terminal.setOption('theme', this.buildTheme());
            terminal.setOption('fontFamily', this.getMonoFont());
            terminal.refresh(0, terminal.rows - 1);
        });
    },

    applyThemeToAll() {
        Object.keys(this.sessionTerminals).forEach(sessionId => {
            this.applyThemeToTerminal(sessionId);
        });
    },

    // Search functionality
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
    }
};

window.TerminalManager = TerminalManager;

// Handle window resize
let resizeTimeout;
window.addEventListener('resize', () => {
    clearTimeout(resizeTimeout);
    resizeTimeout = setTimeout(() => {
        TerminalManager.fitAllTerminals();
    }, 250);
});
