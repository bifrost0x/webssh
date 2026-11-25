(function() {
    'use strict';

    const TerminalSearch = {
        isOpen: false,
        searchBar: null,
        searchInput: null,
        searchCount: null,

        init() {
            this.searchBar = document.getElementById('terminalSearchBar');
            this.searchInput = document.getElementById('terminalSearchInput');
            this.searchCount = document.getElementById('terminalSearchCount');

            if (!this.searchBar || !this.searchInput) return;

            this.searchInput.addEventListener('input', () => {
                this.performSearch();
            });

            this.searchInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    if (e.shiftKey) {
                        this.findPrevious();
                    } else {
                        this.findNext();
                    }
                } else if (e.key === 'Escape') {
                    e.preventDefault();
                    this.close();
                }
            });

            document.getElementById('terminalSearchNext')?.addEventListener('click', () => this.findNext());
            document.getElementById('terminalSearchPrev')?.addEventListener('click', () => this.findPrevious());
            document.getElementById('terminalSearchClose')?.addEventListener('click', () => this.close());
        },

        open() {
            if (SessionManager.isConnectionLauncherOpen?.()) {
                const launcherSearch = document.querySelector(
                    '.terminal-pane.active .profile-launcher-search'
                );
                launcherSearch?.focus();
                launcherSearch?.select();
                return;
            }
            if (!TerminalManager.hasSearchSupport()) {
                showNotification((window.i18n ? window.i18n.t('toast.searchUnavailable') : 'Search not available'), 'warning');
                return;
            }

            const activeSession = SessionManager.getActiveSession();
            if (!activeSession) {
                showNotification((window.i18n ? window.i18n.t('toast.noActiveSession') : 'No active session'), 'warning');
                return;
            }

            this.isOpen = true;
            this.searchBar?.classList.remove('hidden');
            this.searchInput?.focus();
            this.searchInput?.select();
        },

        close() {
            this.isOpen = false;
            this.searchBar?.classList.add('hidden');
            if (this.searchCount) this.searchCount.textContent = '';

            const activeSession = SessionManager.getActiveSession();
            if (activeSession) {
                TerminalManager.clearSearch(activeSession);
            }

            const terminalElement = document.querySelector('.terminal-pane.active .xterm-helper-textarea');
            terminalElement?.focus();
        },

        toggle() {
            if (this.isOpen) {
                this.close();
            } else {
                this.open();
            }
        },

        performSearch() {
            const term = this.searchInput?.value || '';
            const activeSession = SessionManager.getActiveSession();

            if (!activeSession || !term) {
                if (this.searchCount) this.searchCount.textContent = '';
                if (activeSession) TerminalManager.clearSearch(activeSession);
                return;
            }

            const found = TerminalManager.findNext(activeSession, term, { incremental: true });
            if (this.searchCount) {
                this.searchCount.textContent = found ? '' : 'No matches';
            }
        },

        findNext() {
            const term = this.searchInput?.value || '';
            const activeSession = SessionManager.getActiveSession();

            if (!activeSession || !term) return;

            const found = TerminalManager.findNext(activeSession, term, { incremental: false });
            if (this.searchCount) {
                this.searchCount.textContent = found ? '' : 'No matches';
            }
        },

        findPrevious() {
            const term = this.searchInput?.value || '';
            const activeSession = SessionManager.getActiveSession();

            if (!activeSession || !term) return;

            const found = TerminalManager.findPrevious(activeSession, term);
            if (this.searchCount) {
                this.searchCount.textContent = found ? '' : 'No matches';
            }
        }
    };

    window.TerminalSearch = TerminalSearch;
})();
