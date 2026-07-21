(function() {
    'use strict';

    window.addEventListener('unhandledrejection', (e) => {
        console.error('[WebSSH] Unhandled promise rejection:', e.reason);
    });

    window.addEventListener('error', (e) => {
        if (e.filename && e.filename.includes('socket.io')) return;
        console.error('[WebSSH] Uncaught error:', e.message, e.filename, e.lineno);
    });

    const APP_ROOT = document.querySelector('meta[name="app-root"]')?.content || '';
    window.APP_ROOT = APP_ROOT;
    window.socket = io({ path: APP_ROOT + '/socket.io' });

    window.escapeHtml = function(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    };

    window.showNotification = function(message, type = 'info', duration) {
        const container = document.getElementById('notificationContainer');
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.textContent = message;
        container.appendChild(notification);

        const timeout = duration || (type === 'success' || type === 'info' ? 2000 : 3000);
        setTimeout(() => {
            notification.classList.add('fade-out');
            setTimeout(() => notification.remove(), 300);
        }, timeout);
    };

    window.PanelManager = {
        slots: { left: null, right: null },

        open(panelEl) {
            if (!panelEl) return;
            const slot = panelEl.classList.contains('panel-left') ? 'left'
                       : panelEl.classList.contains('panel-right') ? 'right' : null;
            if (slot && this.slots[slot] && this.slots[slot] !== panelEl) {
                this.close(this.slots[slot]);
            }
            if (slot) this.slots[slot] = panelEl;
            panelEl.classList.add('show');
            panelEl.removeAttribute('aria-hidden');
        },

        close(panelEl) {
            if (!panelEl) return;
            panelEl.classList.remove('show');
            panelEl.setAttribute('aria-hidden', 'true');
            const slot = Object.keys(this.slots).find(k => this.slots[k] === panelEl);
            if (slot) this.slots[slot] = null;
        },

        closeAll() {
            Object.values(this.slots).forEach(p => { if (p) this.close(p); });
        }
    };

    window.ModalManager = {
        activeModal: null,
        focusableSelector: 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',

        open(modal) {
            if (!modal) return;
            if (modal.classList.contains('panel-left') || modal.classList.contains('panel-right')) {
                window.PanelManager.open(modal);
                return;
            }
            modal.classList.add('show');
            modal.setAttribute('aria-hidden', 'false');
            this.activeModal = modal;

            const focusable = modal.querySelectorAll(this.focusableSelector);
            if (focusable.length > 0) {
                focusable[0].focus();
            }
        },

        close(modal) {
            if (!modal) return;
            if (modal.classList.contains('panel-left') || modal.classList.contains('panel-right')) {
                window.PanelManager.close(modal);
                return;
            }
            modal.classList.remove('show');
            modal.setAttribute('aria-hidden', 'true');
            if (this.activeModal === modal) {
                this.activeModal = null;
            }
        },

        trapFocus(event) {
            if (!this.activeModal || event.key !== 'Tab') {
                return;
            }
            const focusable = Array.from(this.activeModal.querySelectorAll(this.focusableSelector));
            if (focusable.length === 0) {
                return;
            }
            const first = focusable[0];
            const last = focusable[focusable.length - 1];
            if (event.shiftKey && document.activeElement === first) {
                event.preventDefault();
                last.focus();
            } else if (!event.shiftKey && document.activeElement === last) {
                event.preventDefault();
                first.focus();
            }
        }
    };

    window.clearStartupCommandsInput = () => {
        const startupCommandsInput = document.getElementById('startupCommandsInput');
        if (startupCommandsInput) {
            startupCommandsInput.value = '';
        }
    };

    const ConnectionHistory = {
        maxItems: 10,
        storageKey: 'recentConnections',
        maxAge: 30 * 24 * 60 * 60 * 1000,

        getHistory() {
            try {
                const history = JSON.parse(localStorage.getItem(this.storageKey) || '[]');
                const now = Date.now();
                const filtered = history.filter(entry => {
                    if (!entry.timestamp) return true;
                    return (now - entry.timestamp) < this.maxAge;
                });
                if (filtered.length !== history.length) {
                    localStorage.setItem(this.storageKey, JSON.stringify(filtered));
                }
                return filtered;
            } catch (e) {
                return [];
            }
        },

        addConnection(host, port, username) {
            const history = this.getHistory();
            const entry = { host, port: parseInt(port), username, timestamp: Date.now() };

            const filtered = history.filter(h =>
                !(h.host === host && h.port === parseInt(port) && h.username === username)
            );

            filtered.unshift(entry);

            const trimmed = filtered.slice(0, this.maxItems);

            try {
                localStorage.setItem(this.storageKey, JSON.stringify(trimmed));
            } catch (e) {
                console.error('Failed to save connection history:', e);
            }
        },

        renderHistoryDropdown() {
            const container = document.getElementById('recentConnectionsList');
            if (!container) return;

            const history = this.getHistory();
            container.innerHTML = '';

            if (history.length === 0) {
                container.style.display = 'none';
                return;
            }

            container.style.display = 'block';

            history.forEach(conn => {
                const option = document.createElement('div');
                option.className = 'recent-connection-item';
                option.innerHTML = `
                    <span class="recent-conn-label">${escapeHtml(conn.username)}@${escapeHtml(conn.host)}:${escapeHtml(String(conn.port))}</span>
                    <span class="recent-conn-time">${escapeHtml(this.formatTime(conn.timestamp))}</span>
                `;
                option.addEventListener('click', () => {
                    window.clearStartupCommandsInput();
                    document.getElementById('hostInput').value = conn.host;
                    document.getElementById('portInput').value = conn.port;
                    document.getElementById('usernameInput').value = conn.username;
                    document.getElementById('passwordInput').focus();
                });
                container.appendChild(option);
            });
        },

        formatTime(timestamp) {
            const diff = Date.now() - timestamp;
            const minutes = Math.floor(diff / 60000);
            const hours = Math.floor(diff / 3600000);
            const days = Math.floor(diff / 86400000);

            if (minutes < 1) return window.i18n?.t('time.justNow', 'just now') || 'just now';
            if (minutes < 60) return `${minutes}m`;
            if (hours < 24) return `${hours}h`;
            return `${days}d`;
        }
    };

    window.ConnectionHistory = ConnectionHistory;

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
            if (!TerminalManager.hasSearchSupport()) {
                showNotification('Search not available', 'warning');
                return;
            }

            const activeSession = SessionManager.getActiveSession();
            if (!activeSession) {
                showNotification('No active session', 'warning');
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

    const FilePreview = {
        modal: null,
        currentSessionId: null,
        currentPath: null,
        currentFilename: null,
        editMode: false,
        dirty: false,
        editEncoding: 'utf-8',
        editNewline: 'lf',
        maxEditFileSize: 5 * 1024 * 1024,
        _beforeUnloadHandler: null,

        textExtensions: ['.txt', '.md', '.json', '.yaml', '.yml', '.xml', '.csv', '.ini', '.conf', '.cfg', '.env', '.gitignore', '.dockerignore', '.editorconfig'],
        codeExtensions: ['.js', '.ts', '.jsx', '.tsx', '.py', '.rb', '.php', '.java', '.c', '.cpp', '.h', '.hpp', '.cs', '.go', '.rs', '.swift', '.kt', '.scala', '.sh', '.bash', '.zsh', '.fish', '.ps1', '.bat', '.cmd', '.sql', '.html', '.htm', '.css', '.scss', '.sass', '.less', '.vue', '.svelte'],
        logExtensions: ['.log', '.out', '.err'],
        imageExtensions: ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.ico', '.bmp'],

        init() {
            this.modal = document.getElementById('filePreviewModal');
            if (!this.modal) {
                console.error('[FilePreview] Modal not found: filePreviewModal');
                return;
            }
            console.log('[FilePreview] Initialized successfully');

            const sizeMeta = document.querySelector('meta[name="max-editor-file-size"]');
            const parsedSize = sizeMeta ? parseInt(sizeMeta.content, 10) : NaN;
            if (!isNaN(parsedSize) && parsedSize > 0) {
                this.maxEditFileSize = parsedSize;
            }

            document.getElementById('closeFilePreviewModal')?.addEventListener('click', () => this.close());

            this.modal.addEventListener('click', (e) => {
                if (e.target === this.modal) {
                    this.close();
                }
            });

            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape' && this.modal.classList.contains('show')) {
                    this.close();
                }
            });

            document.getElementById('previewCopyBtn')?.addEventListener('click', () => this.copyToClipboard());
            document.getElementById('previewDownloadBtn')?.addEventListener('click', () => this.downloadFile());
            document.getElementById('previewRefreshBtn')?.addEventListener('click', () => this.refresh());
            document.getElementById('previewBinaryDownload')?.addEventListener('click', () => this.downloadFile());
            document.getElementById('previewEditBtn')?.addEventListener('click', () => this.enterEditMode());
            document.getElementById('editorSaveBtn')?.addEventListener('click', () => this.saveEdit());
            document.getElementById('editorCancelBtn')?.addEventListener('click', () => this.cancelEdit());
            document.getElementById('editorContent')?.addEventListener('input', () => this.markDirty());

            socket.off('preview_data');
            socket.off('preview_error');
            socket.off('edit_data');
            socket.off('edit_error');
            socket.off('file_saved');
            socket.on('preview_data', (data) => {
                this.handlePreviewData(data);
            });
            socket.on('preview_error', (data) => {
                this.handlePreviewError(data);
            });
            socket.on('edit_data', (data) => {
                this.handleEditData(data);
            });
            socket.on('edit_error', (data) => {
                this.handleEditError(data);
            });
            socket.on('file_saved', (data) => {
                this.handleFileSaved(data);
            });
        },

        getFileType(filename) {
            const ext = '.' + filename.split('.').pop().toLowerCase();
            if (this.imageExtensions.includes(ext)) return 'image';
            if (this.logExtensions.includes(ext)) return 'log';
            if (this.codeExtensions.includes(ext)) return 'code';
            if (this.textExtensions.includes(ext)) return 'text';
            if (!filename.includes('.')) return 'text';
            return 'unknown';
        },

        getLanguage(filename) {
            const ext = filename.split('.').pop().toLowerCase();
            const langMap = {
                'js': 'javascript', 'ts': 'typescript', 'jsx': 'javascript', 'tsx': 'typescript',
                'py': 'python', 'rb': 'ruby', 'php': 'php', 'java': 'java',
                'c': 'c', 'cpp': 'cpp', 'h': 'c', 'hpp': 'cpp', 'cs': 'csharp',
                'go': 'go', 'rs': 'rust', 'swift': 'swift', 'kt': 'kotlin', 'scala': 'scala',
                'sh': 'bash', 'bash': 'bash', 'zsh': 'bash', 'fish': 'bash',
                'ps1': 'powershell', 'bat': 'dos', 'cmd': 'dos',
                'sql': 'sql', 'html': 'html', 'htm': 'html', 'xml': 'xml',
                'css': 'css', 'scss': 'scss', 'sass': 'sass', 'less': 'less',
                'json': 'json', 'yaml': 'yaml', 'yml': 'yaml',
                'md': 'markdown', 'vue': 'html', 'svelte': 'html',
                'ini': 'ini', 'conf': 'ini', 'cfg': 'ini',
                'dockerfile': 'dockerfile'
            };
            return langMap[ext] || 'plaintext';
        },

        formatFileSize(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
        },

        open(sessionId, path, filename) {
            console.log('[FilePreview] open called:', { sessionId, path, filename });
            this.currentSessionId = sessionId;
            this.currentPath = path;
            this.currentFilename = filename;

            // Start every open in a clean (non-edit) state.
            this.editMode = false;
            this.dirty = false;
            this.detachBeforeUnload();
            document.getElementById('fileEditor')?.classList.add('hidden');
            this.modal?.classList.remove('editing');
            this.hideEditButton();
            this.showPreviewActions();

            const fileType = this.getFileType(filename);
            console.log('[FilePreview] File type:', fileType);

            this.showLoading();
            window.ModalManager.open(this.modal);

            document.getElementById('previewFilename').textContent = filename;
            document.getElementById('previewSize').textContent = '';

            if (fileType === 'image') {
                console.log('[FilePreview] Loading image...');
                this.loadImage(sessionId, path, filename);
            } else {
                const options = { session_id: sessionId, path: path };

                if (fileType === 'log') {
                    options.tail_lines = 1000;
                }

                console.log('[FilePreview] Emitting preview_file:', options);
                socket.emit('preview_file', options);
            }
        },

        loadImage(sessionId, path, filename) {
            if (this._pendingImageHandler) {
                socket.off('file_download_ready_binary', this._pendingImageHandler);
                this._pendingImageHandler = null;
            }

            const requestPath = path;
            socket.emit('download_file_binary', {
                session_id: sessionId,
                remote_path: path,
                for_preview: true
            });

            const handleBinaryDownload = (data) => {
                if (!data.for_preview) return;

                socket.off('file_download_ready_binary', handleBinaryDownload);
                this._pendingImageHandler = null;

                if (this.currentPath !== requestPath) return;

                if (data.error) {
                    this.showError(data.error);
                    return;
                }

                try {
                    const mimeType = this.getMimeType(filename);
                    let url;

                    if (data.encoding === 'base64') {
                        url = `data:${mimeType};base64,${data.file_data}`;
                    } else {
                        let binaryData = data.file_data;
                        if (binaryData && typeof binaryData === 'object') {
                            if (binaryData.data && Array.isArray(binaryData.data)) {
                                binaryData = new Uint8Array(binaryData.data);
                            } else if (binaryData instanceof ArrayBuffer) {
                                binaryData = new Uint8Array(binaryData);
                            }
                        }
                        const blob = new Blob([binaryData], { type: mimeType });
                        url = URL.createObjectURL(blob);
                    }

                    this.hideLoading();
                    this.showImage(url, data.size);
                } catch (err) {
                    this.showError('Failed to display image: ' + err.message);
                }
            };

            this._pendingImageHandler = handleBinaryDownload;
            socket.on('file_download_ready_binary', handleBinaryDownload);
        },

        getMimeType(filename) {
            const ext = filename.split('.').pop().toLowerCase();
            const mimeTypes = {
                'png': 'image/png', 'jpg': 'image/jpeg', 'jpeg': 'image/jpeg',
                'gif': 'image/gif', 'svg': 'image/svg+xml', 'webp': 'image/webp',
                'ico': 'image/x-icon', 'bmp': 'image/bmp'
            };
            return mimeTypes[ext] || 'application/octet-stream';
        },

        handlePreviewData(data) {
            this.hideLoading();

            document.getElementById('previewSize').textContent = this.formatFileSize(data.size);

            if (data.is_binary) {
                this.hideEditButton();
                this.showBinary();
                return;
            }

            this.showContent(data.content, data.filename, data.truncated, data.read_size, data.size);

            // Entering edit mode re-reads the full file (up to the editor limit)
            // via open_file_for_edit, so a truncated preview is safe to edit.
            // Gate only on the real file size, not on the 512KB preview cap.
            if (data.size <= this.maxEditFileSize) {
                this.showEditButton();
            } else {
                this.hideEditButton();
            }
        },

        handlePreviewError(data) {
            this.hideLoading();
            this.showError(data.error);
        },

        showLoading() {
            document.getElementById('previewLoading')?.classList.remove('hidden');
            document.getElementById('previewError')?.classList.add('hidden');
            document.getElementById('previewBinary')?.classList.add('hidden');
            document.getElementById('previewImage')?.classList.add('hidden');
            document.getElementById('previewContent')?.classList.add('hidden');
            document.getElementById('previewTruncated')?.classList.add('hidden');
            document.getElementById('fileEditor')?.classList.add('hidden');
        },

        hideLoading() {
            document.getElementById('previewLoading')?.classList.add('hidden');
        },

        showError(message) {
            document.getElementById('previewError')?.classList.remove('hidden');
            document.getElementById('previewErrorMessage').textContent = message;
        },

        showBinary() {
            document.getElementById('previewBinary')?.classList.remove('hidden');
        },

        showImage(url, size) {
            const imageContainer = document.getElementById('previewImage');
            const imageElement = document.getElementById('previewImageElement');

            imageContainer?.classList.remove('hidden');
            document.getElementById('previewSize').textContent = this.formatFileSize(size);

            if (imageElement.src && imageElement.src.startsWith('blob:')) {
                URL.revokeObjectURL(imageElement.src);
            }

            imageElement.onload = () => {};
            imageElement.onerror = (e) => {
                imageContainer?.classList.add('hidden');
                this.showError('Failed to load image');
            };

            imageElement.src = url;
        },

        showContent(content, filename, truncated, readSize, totalSize) {
            const contentDiv = document.getElementById('previewContent');
            const codeEl = document.getElementById('previewCode');
            const lineNumbersEl = document.getElementById('previewLineNumbers');

            contentDiv?.classList.remove('hidden');

            // Keep the raw content for an accurate copy; for display, drop a
            // single trailing newline so the file's terminator isn't rendered
            // (and numbered) as a spurious empty last line.
            this._previewFullContent = content;
            const display = content.replace(/\n$/, '');
            codeEl.textContent = display;

            const language = this.getLanguage(filename);
            if (typeof hljs !== 'undefined') {
                codeEl.className = `language-${language}`;
                hljs.highlightElement(codeEl);
            }

            const lineCount = display === '' ? 1 : display.split('\n').length;
            lineNumbersEl.innerHTML = Array.from({ length: lineCount }, (_, i) => i + 1).join('<br>');

            if (truncated) {
                document.getElementById('previewTruncated')?.classList.remove('hidden');
                document.getElementById('previewTruncatedSize').textContent = this.formatFileSize(readSize);
                document.getElementById('previewTotalSize').textContent = this.formatFileSize(totalSize);
            }
        },

        copyToClipboard() {
            const codeEl = document.getElementById('previewCode');
            if (!codeEl) return;

            const text = this._previewFullContent != null ? this._previewFullContent : codeEl.textContent;
            navigator.clipboard.writeText(text).then(() => {
                showNotification('Copied to clipboard', 'success');
            }).catch(() => {
                showNotification('Failed to copy', 'error');
            });
        },

        downloadFile() {
            if (!this.currentSessionId || !this.currentPath) return;

            socket.emit('download_file_binary', {
                session_id: this.currentSessionId,
                remote_path: this.currentPath
            });
        },

        // ---- Inline editor ----
        showEditButton() {
            document.getElementById('previewEditBtn')?.classList.remove('hidden');
        },

        hideEditButton() {
            document.getElementById('previewEditBtn')?.classList.add('hidden');
        },

        showPreviewActions() {
            ['previewCopyBtn', 'previewDownloadBtn', 'previewRefreshBtn'].forEach(id => {
                document.getElementById(id)?.classList.remove('hidden');
            });
        },

        hidePreviewActions() {
            ['previewCopyBtn', 'previewDownloadBtn', 'previewRefreshBtn', 'previewEditBtn'].forEach(id => {
                document.getElementById(id)?.classList.add('hidden');
            });
        },

        attachBeforeUnload() {
            if (this._beforeUnloadHandler) return;
            this._beforeUnloadHandler = (e) => {
                if (this.dirty) {
                    e.preventDefault();
                    e.returnValue = '';
                }
            };
            window.addEventListener('beforeunload', this._beforeUnloadHandler);
        },

        detachBeforeUnload() {
            if (this._beforeUnloadHandler) {
                window.removeEventListener('beforeunload', this._beforeUnloadHandler);
                this._beforeUnloadHandler = null;
            }
        },

        markDirty() {
            if (!this.editMode) return;
            this.dirty = true;
            const status = document.getElementById('editorStatus');
            if (status) {
                status.textContent = window.i18n ? i18n.t('editor.unsavedChanges') : 'Unsaved changes';
            }
        },

        enterEditMode() {
            if (!this.currentSessionId || !this.currentPath) return;
            const status = document.getElementById('editorStatus');
            if (status) status.textContent = '';
            socket.emit('open_file_for_edit', {
                session_id: this.currentSessionId,
                path: this.currentPath
            });
        },

        handleEditData(data) {
            // Ignore responses for a file the user has since navigated away from.
            if (!data || data.path !== this.currentPath) return;

            const textarea = document.getElementById('editorContent');
            if (!textarea) return;

            this.editEncoding = data.encoding || 'utf-8';
            this.editNewline = data.newline || 'lf';
            textarea.value = data.content || '';

            document.getElementById('previewContent')?.classList.add('hidden');
            document.getElementById('previewTruncated')?.classList.add('hidden');
            document.getElementById('previewError')?.classList.add('hidden');
            document.getElementById('fileEditor')?.classList.remove('hidden');
            this.modal?.classList.add('editing');
            this.hidePreviewActions();

            this.editMode = true;
            this.dirty = false;
            const status = document.getElementById('editorStatus');
            if (status) status.textContent = '';
            this.attachBeforeUnload();
            textarea.focus();
        },

        handleEditError(data) {
            const msg = (data && data.error) ? data.error
                : (window.i18n ? i18n.t('editor.saveFailed') : 'Failed to open file');
            showNotification(msg, 'error');
        },

        saveEdit() {
            if (!this.editMode || !this.currentSessionId || !this.currentPath) return;
            const textarea = document.getElementById('editorContent');
            if (!textarea) return;

            const status = document.getElementById('editorStatus');
            if (status) status.textContent = window.i18n ? i18n.t('editor.saving') : 'Saving...';

            socket.emit('save_file', {
                session_id: this.currentSessionId,
                path: this.currentPath,
                content: textarea.value,
                encoding: this.editEncoding,
                newline: this.editNewline
            });
        },

        handleFileSaved(data) {
            if (!data || data.path !== this.currentPath) return;
            this.dirty = false;
            this.detachBeforeUnload();
            showNotification(window.i18n ? i18n.t('editor.saved') : 'File saved', 'success');
            // Leave edit mode and reload the preview to reflect the saved file.
            this.exitEditMode();
            this.refresh();
        },

        cancelEdit() {
            if (this.dirty) {
                const msg = window.i18n ? i18n.t('editor.unsavedConfirm') : 'Discard unsaved changes?';
                if (!window.confirm(msg)) return;
            }
            this.exitEditMode();
            // The preview content is still rendered underneath; just reveal it.
            document.getElementById('previewContent')?.classList.remove('hidden');
        },

        exitEditMode() {
            this.editMode = false;
            this.dirty = false;
            this.detachBeforeUnload();
            document.getElementById('fileEditor')?.classList.add('hidden');
            this.modal?.classList.remove('editing');
            const status = document.getElementById('editorStatus');
            if (status) status.textContent = '';
            this.showPreviewActions();
            this.showEditButton();
        },

        refresh() {
            if (!this.currentSessionId || !this.currentPath) return;

            const filename = this.currentPath.split('/').pop();
            this.open(this.currentSessionId, this.currentPath, filename);
        },

        close() {
            if (this.editMode && this.dirty) {
                const msg = window.i18n ? i18n.t('editor.unsavedConfirm') : 'Discard unsaved changes?';
                if (!window.confirm(msg)) return;
            }
            this.detachBeforeUnload();
            this.editMode = false;
            this.dirty = false;
            document.getElementById('fileEditor')?.classList.add('hidden');
            this.modal?.classList.remove('editing');

            window.ModalManager.close(this.modal);
            this.currentSessionId = null;
            this.currentPath = null;
            this.currentFilename = null;

            const imgEl = document.getElementById('previewImageElement');
            if (imgEl && imgEl.src.startsWith('blob:')) {
                URL.revokeObjectURL(imgEl.src);
                imgEl.src = '';
            }
        }
    };

    window.FilePreview = FilePreview;

    socket.on('connect', () => {
        console.log('Connected to server');
        const reconnectBar = document.getElementById('reconnectBar');
        if (reconnectBar && reconnectBar.style.display !== 'none') {
            reconnectBar.style.display = 'none';
            showNotification('Reconnected!', 'success', 2000);
        }
        if (!keepAliveInterval) {
            keepAliveInterval = setInterval(() => {
                if (socket.connected) {
                    socket.emit('keep_alive');
                }
            }, 60000);
        }
    });

    let keepAliveInterval = setInterval(() => {
        if (socket.connected) {
            socket.emit('keep_alive');
        }
    }, 60000);

    socket.io.on('reconnect_attempt', (attempt) => {
        const reconnectBar = document.getElementById('reconnectBar');
        if (reconnectBar) {
            const textEl = reconnectBar.querySelector('.reconnect-text');
            if (textEl) {
                textEl.textContent = `Connection lost. Reconnecting... (attempt ${attempt})`;
            }
        }
    });

    socket.on('connected', (data) => {
        if (data && data.status === 'success' && window.socket) {
            window.socket.emit('get_notepad');
        }
    });

    socket.on('disconnect', () => {
        console.log('Disconnected from server');
        showNotification('Disconnected from server', 'error');
        const reconnectBar = document.getElementById('reconnectBar');
        if (reconnectBar) {
            reconnectBar.style.display = 'flex';
        }
        if (keepAliveInterval) {
            clearInterval(keepAliveInterval);
            keepAliveInterval = null;
        }
    });

    socket.on('ssh_connected', (data) => {
        console.log('SSH connected:', data);

        if (data.client_request_id) {
            SessionManager.clearPendingConnection(data.client_request_id);
        }

        if (connectTimer) {
            clearInterval(connectTimer);
            connectTimer = null;
            const connectBtn = document.getElementById('connectBtn');
            if (connectBtn) {
                connectBtn.textContent = 'Connect';
            }
        }

        setConnectLoading(false);
        currentConnectRequestId = null;

        const sessionId = SessionManager.createSession(data);

        let targetPane = null;
        if (data.client_request_id && pendingRequestPaneMap.has(data.client_request_id)) {
            targetPane = pendingRequestPaneMap.get(data.client_request_id);
            pendingRequestPaneMap.delete(data.client_request_id);
        }
        if (targetPane === null || targetPane === undefined) {
            const emptyIndex = SessionManager.getFirstEmptyPaneIndex();
            targetPane = emptyIndex !== -1 ? emptyIndex : SessionManager.getActivePaneIndex();
        }
        SessionManager.assignSessionToPane(sessionId, targetPane);

        window.ModalManager.close(document.getElementById('connectionModal'));
        processPaneQueue();

        const connMsg = data.via_jump
            ? `Connected to ${data.username}@${data.host} via ${data.via_jump}`
            : `Connected to ${data.username}@${data.host}`;
        showNotification(connMsg, 'success');

        ConnectionHistory.addConnection(data.host, data.port, data.username);

        FileTransferManager.updateSessionSelects();
    });

    socket.on('ssh_output', (data) => {
        console.log(`[SSH_OUTPUT] Received for session ${data.session_id}, length: ${data.data.length}`);
        TerminalManager.writeOutput(data.session_id, data.data);

    });

    socket.on('ssh_error', (data) => {
        console.error('SSH error:', data);
        showNotification(`SSH Error: ${data.error}`, 'error');

        if (connectTimer) {
            clearInterval(connectTimer);
            connectTimer = null;
            const connectBtn = document.getElementById('connectBtn');
            if (connectBtn) {
                connectBtn.textContent = 'Connect';
            }
        }

        setConnectLoading(false);
        const requestId = data.client_request_id || currentConnectRequestId;
        if (requestId) {
            SessionManager.clearPendingConnection(requestId);
            if (requestId === currentConnectRequestId) {
                currentConnectRequestId = null;
            }
            if (pendingRequestPaneMap.has(requestId)) {
                pendingRequestPaneMap.delete(requestId);
            }
        }
    });

    socket.on('ssh_disconnected', (data) => {
        console.log('SSH disconnected:', data);
        showNotification(`Session disconnected: ${data.reason}`, 'warning');
        SessionManager.updateSessionStatus(data.session_id, 'disconnected');
        FileTransferManager.updateSessionSelects();

        if (window.sftpFileManager) {
            window.sftpFileManager.handleSessionDisconnected(data.session_id);
        }
    });

    socket.on('session_timeout_warning', (data) => {
        showNotification(`Session "${data.session_id.substr(0,8)}..." will timeout in 2 minutes due to inactivity. Type anything to keep alive.`, 'warning', 10000);
    });

    socket.on('profiles_list', (data) => {
        ProfileManager.setProfiles(data.profiles);
    });

    socket.on('profile_saved', (data) => {
        showNotification('Profile saved successfully', 'success');
    });

    socket.on('profile_deleted', (data) => {
        showNotification('Profile deleted successfully', 'success');
    });

    socket.on('keys_list', (data) => {
        ProfileManager.setKeys(data.keys);
    });

    socket.on('key_uploaded', (data) => {
        showNotification('SSH key uploaded successfully', 'success');
        document.getElementById('keyUploadForm').reset();
    });

    socket.on('key_deleted', (data) => {
        showNotification('SSH key deleted successfully', 'success');
    });

    socket.on('jump_hosts_list', (data) => {
        if (window.JumpHostManager) window.JumpHostManager.setJumpHosts(data.jump_hosts);
    });

    socket.on('jump_host_saved', (data) => {
        showNotification(window.i18n ? i18n.t('jumphosts.savedOk') : 'Jump host saved', 'success');
        document.getElementById('jumpHostForm')?.reset();
        document.getElementById('jhKeyGroup')?.classList.add('hidden');
    });

    socket.on('jump_host_deleted', (data) => {
        showNotification(window.i18n ? i18n.t('jumphosts.deleted') : 'Jump host deleted', 'success');
    });

    socket.on('file_progress', (data) => {
        FileTransferManager.updateProgress(data);
    });

    socket.on('file_complete', (data) => {
        FileTransferManager.handleTransferComplete(data);
    });

    socket.on('file_download_ready', (data) => {
        FileTransferManager.handleDownloadReady(data);
    });

    socket.on('error', (data) => {
        if (window.sftpFileManager && window.sftpFileManager.isOpen) return;
        showNotification(`Error: ${data.error}`, 'error');
    });

    socket.on('notepad_data', (data) => {
        const notepad = document.getElementById('sessionNotepad');
        if (!notepad) {
            return;
        }
        notepad.value = (data && data.notepad) ? data.notepad : '';
    });

    let currentConnectRequestId = null;
    let pendingPaneIndex = null;
    const pendingPaneQueue = [];
    const pendingRequestPaneMap = new Map();
    let connectTimer = null;
    let connectSeconds = 0;

    function openConnectionModalForPane(paneIndex) {
        window.clearStartupCommandsInput();
        pendingPaneIndex = paneIndex;
        if (paneIndex !== null && paneIndex !== undefined) {
            SessionManager.setActivePane(paneIndex);
        }

        // Reset the jump host selection so a previous jump never carries into a
        // new connection by accident.
        const jumpHostSelect = document.getElementById('jumpHostSelect');
        if (jumpHostSelect) {
            jumpHostSelect.value = '';
            document.getElementById('jumpHostPasswordGroup')?.classList.add('hidden');
        }

        ConnectionHistory.renderHistoryDropdown();
        const historyGroup = document.getElementById('recentConnectionsGroup');
        if (historyGroup) {
            historyGroup.style.display = ConnectionHistory.getHistory().length > 0 ? 'block' : 'none';
        }

        const modal = document.getElementById('connectionModal');
        if (window.ModalManager) {
            window.ModalManager.open(modal);
        } else {
            modal.classList.add('show');
        }
        setConnectLoading(false);
    }

    function queuePaneConnection(paneIndex) {
        if (paneIndex === null || paneIndex === undefined) {
            return;
        }
        if (pendingPaneQueue.includes(paneIndex)) {
            return;
        }
        pendingPaneQueue.push(paneIndex);
        processPaneQueue();
    }

    function processPaneQueue() {
        if (currentConnectRequestId || pendingPaneIndex !== null) {
            return;
        }
        if (pendingPaneQueue.length === 0) {
            return;
        }
        const nextPane = pendingPaneQueue.shift();
        openConnectionModalForPane(nextPane);
    }

    function clearPaneQueue() {
        pendingPaneQueue.length = 0;
        pendingPaneIndex = null;
    }

    function getDefaultPaneIndex() {
        const activeIndex = SessionManager.getActivePaneIndex();
        const activeSession = SessionManager.getActiveSession();
        if (!activeSession && activeIndex !== null && activeIndex !== undefined) {
            return activeIndex;
        }
        const emptyIndex = SessionManager.getFirstEmptyPaneIndex();
        if (emptyIndex !== -1) {
            return emptyIndex;
        }
        return activeIndex !== null && activeIndex !== undefined ? activeIndex : 0;
    }

    window.openConnectionModalForPane = openConnectionModalForPane;

    function setConnectLoading(isLoading) {
        const connectBtn = document.getElementById('connectBtn');
        const spinner = document.getElementById('connectSpinner');
        if (!connectBtn || !spinner) {
            return;
        }
        connectBtn.disabled = isLoading;
        spinner.classList.toggle('hidden', !isLoading);
    }

    function setFieldState(input, hintEl, message, isValid) {
        if (!input || !hintEl) {
            return;
        }
        input.classList.toggle('is-valid', Boolean(isValid));
        input.classList.toggle('is-invalid', isValid === false);
        hintEl.textContent = message || '';
        hintEl.classList.toggle('hint-error', isValid === false);
        hintEl.classList.toggle('hint-success', isValid === true);
    }

    function setupConnectionValidation() {
        const hostInput = document.getElementById('hostInput');
        const portInput = document.getElementById('portInput');
        const userInput = document.getElementById('usernameInput');
        const passwordInput = document.getElementById('passwordInput');
        const keySelect = document.getElementById('keySelect');
        const profileNameInput = document.getElementById('profileNameInput');
        const authTypeSelect = document.getElementById('authTypeSelect');

        if (!hostInput || !portInput || !userInput) {
            return;
        }

        const hostHint = document.getElementById('hostHint');
        const portHint = document.getElementById('portHint');
        const userHint = document.getElementById('usernameHint');
        const passHint = document.getElementById('passwordHint');
        const keyHint = document.getElementById('keyHint');
        const profileHint = document.getElementById('profileHint');

        const hostnamePattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
        const usernamePattern = /^[a-zA-Z0-9_-]{1,32}$/;

        hostInput.addEventListener('input', () => {
            const value = hostInput.value.trim();
            const isValid = value && (hostnamePattern.test(value) || ipPattern.test(value));
            setFieldState(hostInput, hostHint, isValid ? '✓ Valid host' : 'Hostname or IP required', isValid);
        });

        portInput.addEventListener('input', () => {
            const value = parseInt(portInput.value, 10);
            const isValid = value >= 1 && value <= 65535;
            setFieldState(portInput, portHint, isValid ? '✓ Valid port' : 'Port 1-65535', isValid);
        });

        userInput.addEventListener('input', () => {
            const value = userInput.value.trim();
            const isValid = usernamePattern.test(value);
            setFieldState(userInput, userHint, isValid ? '✓ Valid username' : '1-32 chars, a-z 0-9 _ -', isValid);
        });

        if (passwordInput) {
            passwordInput.addEventListener('input', () => {
                const value = passwordInput.value;
                const isValid = value.length > 0;
                setFieldState(passwordInput, passHint, isValid ? '✓ Ready' : 'Password required', isValid);
            });
        }

        if (keySelect) {
            keySelect.addEventListener('change', () => {
                const value = keySelect.value;
                setFieldState(keySelect, keyHint, value ? '✓ Key selected' : 'Select a key', Boolean(value));
            });
        }

        if (profileNameInput) {
            profileNameInput.addEventListener('input', () => {
                const value = profileNameInput.value.trim();
                setFieldState(profileNameInput, profileHint, value ? '✓ Saved name' : '', value ? true : null);
            });
        }

        if (authTypeSelect) {
            authTypeSelect.addEventListener('change', () => {
                if (authTypeSelect.value === 'password' && passwordInput) {
                    setFieldState(passwordInput, passHint, passwordInput.value ? '✓ Ready' : 'Password required', Boolean(passwordInput.value));
                }
                if (authTypeSelect.value === 'key' && keySelect) {
                    setFieldState(keySelect, keyHint, keySelect.value ? '✓ Key selected' : 'Select a key', Boolean(keySelect.value));
                }
            });
        }
    }

    function setupPasswordToggles() {
        document.querySelectorAll('.password-toggle').forEach(button => {
            button.addEventListener('click', () => {
                const targetId = button.dataset.target;
                const input = document.getElementById(targetId);
                if (!input) {
                    return;
                }
                const isHidden = input.getAttribute('type') === 'password';
                input.setAttribute('type', isHidden ? 'text' : 'password');
                button.classList.toggle('active', isHidden);
            });
        });
    }

    function setupClipboardActions() {
        const copyBtn = document.getElementById('copySelectionBtn');
        const pasteBtn = document.getElementById('pasteClipboardBtn');
        const saveBtn = document.getElementById('saveTranscriptBtn');

        if (copyBtn) {
            copyBtn.addEventListener('click', () => {
                const active = SessionManager.getActiveSession();
                const terminal = SessionManager.getActiveTerminal();
                if (!active || !terminal) {
                    showNotification('No active session', 'warning');
                    return;
                }
                const selection = terminal ? terminal.getSelection() : '';
                if (!selection) {
                    showNotification('Nothing selected to copy', 'info');
                    return;
                }
                navigator.clipboard.writeText(selection)
                    .then(() => showNotification('Selection copied', 'success'))
                    .catch(() => showNotification('Clipboard access denied', 'error'));
            });
        }

        if (pasteBtn) {
            pasteBtn.addEventListener('click', () => {
                const active = SessionManager.getActiveSession();
                if (!active) {
                    showNotification('No active session', 'warning');
                    return;
                }
                navigator.clipboard.readText()
                    .then(text => {
                        if (window.socket && text) {
                            window.socket.emit('ssh_input', { session_id: active, data: text });
                        }
                    })
                    .catch(() => showNotification('Clipboard access denied', 'error'));
            });
        }

        if (saveBtn) {
            saveBtn.addEventListener('click', () => {
                const active = SessionManager.getActiveSession();
                if (!active) {
                    showNotification('No active session', 'warning');
                    return;
                }
                const transcript = TerminalManager.getCleanTranscript(active);
                if (!transcript) {
                    showNotification('Transcript is empty', 'info');
                    return;
                }
                const blob = new Blob([transcript], { type: 'text/plain;charset=utf-8' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `session-${active}.txt`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                showNotification('Transcript saved', 'success');
            });
        }

        const mobileInput = document.getElementById('mobileInput');
        const mobileSendBtn = document.getElementById('mobileSendBtn');

        const sendMobileInput = () => {
            const active = SessionManager.getActiveSession();
            if (!active || !mobileInput.value) return;
            if (window.socket) {
                window.socket.emit('ssh_input', { session_id: active, data: mobileInput.value + '\r' });
            }
            mobileInput.value = '';
        };

        if (mobileInput) {
            mobileInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    sendMobileInput();
                }
            });
        }

        if (mobileSendBtn) {
            mobileSendBtn.addEventListener('click', sendMobileInput);
        }

    }

    function setupSplitControls() {
        document.querySelectorAll('.split-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const layout = parseInt(btn.dataset.layout, 10);
                const currentLayout = SessionManager.layout;

                if (layout !== currentLayout && SessionManager.hasAnySessions()) {
                    SessionManager.showPaneAssignmentModal(layout);
                } else {
                    SessionManager.setSplitLayout(layout);
                }
            });
        });
    }

    function setupNotepad() {
        const notepad = document.getElementById('sessionNotepad');
        const saveStatus = document.getElementById('notepadSaveStatus');
        if (!notepad) {
            return;
        }

        const updateSaveStatus = (status) => {
            if (!saveStatus) return;
            if (status === 'saving') {
                saveStatus.textContent = 'Saving...';
                saveStatus.className = 'notepad-save-status saving';
            } else if (status === 'saved') {
                saveStatus.textContent = '✓ Saved';
                saveStatus.className = 'notepad-save-status saved';
                setTimeout(() => {
                    saveStatus.className = 'notepad-save-status';
                    saveStatus.textContent = '';
                }, 2000);
            }
        };

        notepad.addEventListener('focus', () => {
            if (document.body.classList.contains('keyboard-open')) {
                document.body.classList.add('notepad-focused');
            }
        });
        notepad.addEventListener('blur', () => {
            document.body.classList.remove('notepad-focused');
        });

        let timer;
        notepad.addEventListener('input', () => {
            clearTimeout(timer);
            const value = notepad.value;
            updateSaveStatus('saving');
            timer = setTimeout(() => {
                if (window.socket) {
                    window.socket.emit('save_notepad', { text: value });
                    updateSaveStatus('saved');
                }
            }, 300);
        });
    }

    function setupResizeHandle() {
        const handle = document.getElementById('resizeHandle');
        const workspace = document.getElementById('workspace');
        const terminalArea = workspace.querySelector('.terminal-area');
        const notepadPanel = document.getElementById('notepadPanel');

        if (!handle || !workspace || !terminalArea || !notepadPanel) {
            return;
        }

        let isResizing = false;
        let startX = 0;
        let startNotepadWidth = 0;

        const saveLayout = (notepadWidth) => {
            localStorage.setItem('workspace-notepad-width', String(Math.round(notepadWidth)));
        };

        const loadLayout = () => {
            const notepadWidth = parseFloat(localStorage.getItem('workspace-notepad-width'));
            if (!Number.isNaN(notepadWidth) && notepadWidth > 0) {
                workspace.style.setProperty('--notepad-width', `${notepadWidth}px`);
            }
        };

        const startResize = (e) => {
            if (e.target.closest('.notepad-toggle-btn')) {
                return;
            }

            isResizing = true;
            startX = e.clientX ?? e.touches?.[0]?.clientX ?? 0;
            startNotepadWidth = notepadPanel.offsetWidth;

            document.body.style.cursor = 'col-resize';
            document.body.style.userSelect = 'none';

            if (e.pointerId !== undefined) {
                handle.setPointerCapture(e.pointerId);
            }

            e.preventDefault();
        };

        const resize = (e) => {
            if (!isResizing) {
                return;
            }

            const clientX = e.clientX ?? e.touches?.[0]?.clientX ?? 0;
            const deltaX = clientX - startX;
            const workspaceWidth = workspace.offsetWidth;

            let newNotepadWidth = startNotepadWidth - deltaX;

            const minNotepadWidth = 180;
            const maxNotepadWidth = workspaceWidth * 0.6;
            const minTerminalWidth = workspaceWidth * 0.3;

            newNotepadWidth = Math.max(minNotepadWidth, Math.min(maxNotepadWidth, newNotepadWidth));
            let newTerminalWidth = workspaceWidth - newNotepadWidth;

            if (newTerminalWidth < minTerminalWidth) {
                newTerminalWidth = minTerminalWidth;
                newNotepadWidth = workspaceWidth - minTerminalWidth;
            }

            workspace.style.setProperty('--notepad-width', `${newNotepadWidth}px`);

            if (SessionManager.hasAnySessions()) {
                const activeSessionId = SessionManager.getActiveSession();
                if (activeSessionId) {
                    setTimeout(() => {
                        TerminalManager.fitTerminal(activeSessionId);
                        const size = TerminalManager.getTerminalSize(activeSessionId);
                        if (size && window.socket) {
                            window.socket.emit('ssh_resize', {
                                session_id: activeSessionId,
                                rows: size.rows,
                                cols: size.cols
                            });
                        }
                    }, 50);
                }
            }

            e.preventDefault();
        };

        const stopResize = () => {
            if (!isResizing) {
                return;
            }

            isResizing = false;
            document.body.style.cursor = '';
            document.body.style.userSelect = '';

            const notepadWidth = notepadPanel.getBoundingClientRect().width;
            if (!Number.isNaN(notepadWidth) && notepadWidth > 0) {
                saveLayout(notepadWidth);
            }
        };

        handle.addEventListener('pointerdown', startResize);
        document.addEventListener('pointermove', resize);
        document.addEventListener('pointerup', stopResize);
        document.addEventListener('pointercancel', stopResize);

        handle.style.touchAction = 'none';

        loadLayout();

        const notepadToggle = document.getElementById('notepadToggle');
        if (notepadToggle && notepadPanel) {
            const initiallyCollapsed = localStorage.getItem('notepadCollapsed') === 'true';
            if (initiallyCollapsed) {
                notepadPanel.classList.add('collapsed');
                notepadToggle.textContent = '▶';
            }
            notepadToggle.setAttribute('aria-expanded', String(!initiallyCollapsed));
            notepadToggle.addEventListener('pointerdown', (e) => {
                e.stopPropagation();
            });
            notepadToggle.addEventListener('click', (e) => {
                e.stopPropagation();
                notepadPanel.classList.toggle('collapsed');
                const isCollapsed = notepadPanel.classList.contains('collapsed');
                notepadToggle.textContent = isCollapsed ? '▶' : '◀';
                notepadToggle.setAttribute('aria-expanded', String(!isCollapsed));
                localStorage.setItem('notepadCollapsed', isCollapsed);
                setTimeout(() => {
                    if (window.TerminalManager) {
                        TerminalManager.fitAllTerminals();
                    }
                }, 300);
            });
        }

        handle.addEventListener('dblclick', (e) => {
            if (e.target.closest('.notepad-toggle-btn')) {
                return;
            }

            workspace.style.removeProperty('--notepad-width');
            localStorage.removeItem('workspace-notepad-width');
            showNotification('Layout reset to default', 'info');

            if (SessionManager.hasAnySessions()) {
                const activeSessionId = SessionManager.getActiveSession();
                if (activeSessionId) {
                    setTimeout(() => {
                        TerminalManager.fitTerminal(activeSessionId);
                    }, 50);
                }
            }
        });
    }

    function setupDropUpload() {
        const overlay = document.getElementById('dropOverlay');
        const form = document.getElementById('dropUploadForm');
        const fileNameInput = document.getElementById('dropUploadFileName');
        const pathInput = document.getElementById('dropUploadPath');
        const modal = document.getElementById('dropUploadModal');
        let pendingFile = null;

        if (!overlay || !form || !modal) {
            return;
        }

        const showOverlay = () => overlay.classList.remove('hidden');
        const hideOverlay = () => overlay.classList.add('hidden');

        document.addEventListener('dragover', (e) => {
            if (e.dataTransfer && Array.from(e.dataTransfer.types).includes('Files')) {
                e.preventDefault();
                showOverlay();
            }
        });

        document.addEventListener('dragleave', (e) => {
            if (e.target === document.documentElement) {
                hideOverlay();
            }
        });

        document.addEventListener('dragend', () => {
            hideOverlay();
        });

        document.addEventListener('drop', (e) => {
            e.preventDefault();
            hideOverlay();

            const active = SessionManager.getActiveSession();
            if (!active) {
                showNotification('No active session for upload', 'warning');
                return;
            }

            const file = e.dataTransfer.files && e.dataTransfer.files[0];
            if (!file) {
                return;
            }
            pendingFile = file;
            fileNameInput.value = file.name;
            pathInput.value = `./${file.name}`;

            if (window.ModalManager) {
                window.ModalManager.open(modal);
            } else {
                modal.classList.add('show');
            }
        });

        form.addEventListener('submit', (e) => {
            e.preventDefault();
            const active = SessionManager.getActiveSession();
            if (!active || !pendingFile) {
                showNotification('No active session for upload', 'warning');
                return;
            }
            const remotePath = pathInput.value.trim();
            if (!remotePath) {
                showNotification('Remote path required', 'error');
                return;
            }
            FileTransferManager.uploadFile(active, pendingFile, remotePath);
            pendingFile = null;
            if (window.ModalManager) {
                window.ModalManager.close(modal);
            } else {
                modal.classList.remove('show');
            }
        });

        document.getElementById('cancelDropUploadBtn').addEventListener('click', () => {
            pendingFile = null;
            if (window.ModalManager) {
                window.ModalManager.close(modal);
            } else {
                modal.classList.remove('show');
            }
        });

        document.getElementById('closeDropUploadModal').addEventListener('click', () => {
            pendingFile = null;
            if (window.ModalManager) {
                window.ModalManager.close(modal);
            } else {
                modal.classList.remove('show');
            }
        });
    }

    function setupShortcutsModal() {
        const modal = document.getElementById('shortcutsModal');
        const list = document.getElementById('shortcutsList');
        const shortcuts = [
            { keys: 'F1', label: 'Open Command Library' },
            { keys: 'Ctrl+K', label: 'Open Command Palette' },
            { keys: 'Ctrl+?', label: 'Show Shortcuts' },
            { keys: 'Ctrl+Shift+N', label: 'New Connection' },
            { keys: 'Ctrl+F', label: 'Search in Terminal' },
            { keys: 'Ctrl/Cmd+C', label: 'Copy terminal selection' },
            { keys: 'Ctrl/Cmd+V', label: 'Paste into terminal' },
            { keys: 'Ctrl+1-9', label: 'Switch to tab 1-9' },
            { keys: 'Ctrl+Tab', label: 'Next tab' },
            { keys: 'Ctrl+Shift+Tab', label: 'Previous tab' },
            { keys: 'F2', label: 'Rename file (in File Manager)' },
            { keys: 'F5', label: 'Transfer file (in File Manager)' },
            { keys: 'F7', label: 'New folder (in File Manager)' },
            { keys: 'Delete', label: 'Delete selected (in File Manager)' },
            { keys: 'Tab', label: 'Switch pane (in File Manager)' },
            { keys: 'Ctrl+A', label: 'Select all (in File Manager)' },
            { keys: 'Esc', label: 'Close modals' }
        ];
        if (!list) {
            return;
        }
        list.innerHTML = '';
        shortcuts.forEach(shortcut => {
            const row = document.createElement('div');
            row.className = 'shortcut-row';
            row.innerHTML = `<strong>${shortcut.keys}</strong><span>${shortcut.label}</span>`;
            list.appendChild(row);
        });

        const closeBtn = document.getElementById('closeShortcutsModal');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                window.ModalManager.close(modal);
            });
        }

        return modal;
    }

    function setupCommandPalette() {
        const modal = document.getElementById('commandPaletteModal');
        const input = document.getElementById('commandPaletteInput');
        const list = document.getElementById('commandPaletteList');
        if (!modal || !input || !list) {
            return null;
        }

        const actions = [
            { label: 'New Connection', hint: 'Ctrl+Shift+N', action: () => document.getElementById('newConnectionBtn').click() },
            { label: 'Command Library', hint: 'F1', action: () => CommandLibrary.openLibrary() },
            { label: 'File Transfer', hint: '', action: () => document.getElementById('fileTransferBtn').click() },
            { label: 'Manage Keys', hint: '', action: () => document.getElementById('manageKeysBtn').click() },
            { label: 'Change Password', hint: '', action: () => document.getElementById('changePasswordBtn').click() },
            { label: 'Save Transcript', hint: '', action: () => document.getElementById('saveTranscriptBtn').click() },
            { label: 'Copy Selection', hint: '', action: () => document.getElementById('copySelectionBtn').click() },
            { label: 'Paste Clipboard', hint: '', action: () => document.getElementById('pasteClipboardBtn').click() },
            { label: 'Shortcuts Help', hint: 'Ctrl+?', action: () => openShortcuts() }
        ];

        let filtered = actions;
        let activeIndex = 0;

        function render() {
            list.innerHTML = '';
            if (filtered.length === 0) {
                const empty = document.createElement('div');
                empty.className = 'palette-item';
                empty.textContent = 'No matches';
                list.appendChild(empty);
                return;
            }
            filtered.forEach((item, index) => {
                const el = document.createElement('div');
                el.className = 'palette-item' + (index === activeIndex ? ' active' : '');
                el.innerHTML = `${item.label}<span>${item.hint}</span>`;
                el.addEventListener('click', () => {
                    item.action();
                    closePalette();
                });
                list.appendChild(el);
            });
        }

        function openPalette() {
            input.value = '';
            filtered = actions;
            activeIndex = 0;
            render();
            window.ModalManager.open(modal);
            setTimeout(() => input.focus(), 50);
        }

        function closePalette() {
            window.ModalManager.close(modal);
        }

        input.addEventListener('input', () => {
            const query = input.value.trim().toLowerCase();
            filtered = actions.filter(item => item.label.toLowerCase().includes(query));
            activeIndex = 0;
            render();
        });

        input.addEventListener('keydown', (e) => {
            if (e.key === 'ArrowDown') {
                activeIndex = Math.min(activeIndex + 1, filtered.length - 1);
                render();
                e.preventDefault();
            } else if (e.key === 'ArrowUp') {
                activeIndex = Math.max(activeIndex - 1, 0);
                render();
                e.preventDefault();
            } else if (e.key === 'Enter') {
                const item = filtered[activeIndex];
                if (item) {
                    item.action();
                    closePalette();
                }
            } else if (e.key === 'Escape') {
                closePalette();
            }
        });

        document.getElementById('closeCommandPaletteModal').addEventListener('click', () => closePalette());
        return openPalette;
    }

    let openShortcuts = null;
    let shortcutsModal = null;
    let openPalette = null;

    document.addEventListener('DOMContentLoaded', () => {
        const reconnectBar = document.createElement('div');
        reconnectBar.id = 'reconnectBar';
        reconnectBar.className = 'reconnect-bar';
        reconnectBar.style.display = 'none';
        reconnectBar.innerHTML = '<span class="reconnect-text">Connection lost. Reconnecting...</span>';
        const header = document.querySelector('.header');
        if (header) {
            header.after(reconnectBar);
        }

        SessionManager.init();

        CommandLibrary.init();

        ProfileManager.loadProfiles();
        ProfileManager.loadKeys();
        if (window.JumpHostManager) {
            window.JumpHostManager.load();
        }

        document.getElementById('newConnectionBtn').addEventListener('click', () => {
            openConnectionModalForPane(getDefaultPaneIndex());
        });

        const newTabBtn = document.getElementById('newTabBtn');
        if (newTabBtn) {
            newTabBtn.addEventListener('click', () => {
                document.getElementById('newConnectionBtn').click();
            });
        }

        document.getElementById('closeConnectionModal').addEventListener('click', () => {
            window.ModalManager.close(document.getElementById('connectionModal'));
            setConnectLoading(false);
            currentConnectRequestId = null;
            clearPaneQueue();
            if (connectTimer) { clearInterval(connectTimer); connectTimer = null; }
        });

        document.getElementById('cancelConnectionBtn').addEventListener('click', () => {
            window.ModalManager.close(document.getElementById('connectionModal'));
            setConnectLoading(false);
            currentConnectRequestId = null;
            clearPaneQueue();
            if (connectTimer) { clearInterval(connectTimer); connectTimer = null; }
        });

        document.getElementById('connectionForm').addEventListener('submit', (e) => {
            e.preventDefault();

            const host = document.getElementById('hostInput').value;
            const port = document.getElementById('portInput').value;
            const username = document.getElementById('usernameInput').value;
            const authType = document.getElementById('authTypeSelect').value;
            const password = document.getElementById('passwordInput').value;
            const keyId = document.getElementById('keySelect').value;
            const saveProfile = document.getElementById('saveProfileCheck').checked;
            const profileName = document.getElementById('profileNameInput').value;
            const startupCommands = document.getElementById('startupCommandsInput').value;
            const targetPane = pendingPaneIndex;
            pendingPaneIndex = null;

            if (!host || !username) {
                showNotification('Host and username are required', 'error');
                return;
            }

            if (authType === 'password' && !password) {
                showNotification('Password is required', 'error');
                return;
            }

            if (authType === 'key' && !keyId) {
                showNotification('SSH key is required', 'error');
                return;
            }

            // Optional jump host (bastion) — chosen from the saved list
            const jumpHostId = document.getElementById('jumpHostSelect').value;
            let proxyJump = null;
            if (jumpHostId) {
                const jh = window.JumpHostManager ? window.JumpHostManager.getById(jumpHostId) : null;
                if (!jh) {
                    showNotification('Selected jump host not found', 'error');
                    return;
                }
                proxyJump = {
                    host: jh.host,
                    port: jh.port,
                    username: jh.username,
                    auth_type: jh.auth_type
                };
                if (jh.auth_type === 'password') {
                    const jhPass = document.getElementById('jumpHostPasswordInput').value;
                    if (!jhPass) {
                        showNotification('Jump host password is required', 'error');
                        return;
                    }
                    proxyJump.password = jhPass;
                } else {
                    proxyJump.key_id = jh.key_id;
                }
            }

            if (saveProfile && profileName) {
                const profilePayload = {
                    name: profileName,
                    host: host,
                    port: parseInt(port),
                    username: username,
                    auth_type: authType,
                    key_id: authType === 'key' ? keyId : null
                };
                profilePayload.startup_commands = startupCommands;
                if (jumpHostId) {
                    profilePayload.jump_host_id = jumpHostId;
                }
                ProfileManager.saveProfile(profilePayload);
            }

            currentConnectRequestId = `req_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`;
            SessionManager.createPendingConnection(currentConnectRequestId, host, username, port);
            if (targetPane !== null && targetPane !== undefined) {
                pendingRequestPaneMap.set(currentConnectRequestId, targetPane);
            }

            const connectionData = {
                host: host,
                port: parseInt(port),
                username: username,
                client_request_id: currentConnectRequestId,
                auth_type: authType
            };
            connectionData.startup_commands = startupCommands;

            if (authType === 'password') {
                connectionData.password = password;
            } else if (authType === 'key') {
                connectionData.key_id = keyId;
            }

            if (proxyJump) {
                connectionData.proxy_jump = proxyJump;
            }

            const useTmuxCheck = document.getElementById('useTmuxCheck');
            if (useTmuxCheck && useTmuxCheck.checked) {
                connectionData.use_tmux = true;
                // Include tmux session name for reconnection to persistent sessions
                if (SessionManager.pendingReconnectTmux) {
                    connectionData.reconnect_tmux_name = SessionManager.pendingReconnectTmux;
                    SessionManager.pendingReconnectTmux = null;
                }
                // Include display name for reconnecting persistent sessions
                if (SessionManager.pendingDisplayName) {
                    connectionData.display_name = SessionManager.pendingDisplayName;
                    SessionManager.pendingDisplayName = null;
                }
            }

            const connectBtn = document.getElementById('connectBtn');
            const originalText = connectBtn.textContent;
            connectSeconds = 0;
            connectBtn.textContent = 'Connecting... 0s';
            connectTimer = setInterval(() => {
                connectSeconds++;
                connectBtn.textContent = `Connecting... ${connectSeconds}s`;
            }, 1000);

            // Clean up any persistent candidate tab for the same host/port/user
            // Use removeSessionUI to avoid emitting ssh_disconnect which would
            // delete the DB record and lose the session display name.
            Object.keys(SessionManager.sessions).forEach(sid => {
                const s = SessionManager.sessions[sid];
                if (s && s.isPersistentCandidate && s.host === host && s.port === parseInt(port) && s.username === username) {
                    SessionManager.removeSessionUI(sid);
                }
            });

            socket.emit('ssh_connect', connectionData);
            setConnectLoading(true);

            document.getElementById('passwordInput').value = '';
            document.getElementById('jumpHostPasswordInput').value = '';
        });

        document.getElementById('profileSelect').addEventListener('change', (e) => {
            const profileId = e.target.value;
            const deleteBtn = document.getElementById('deleteProfileBtn');

            if (profileId) {
                ProfileManager.selectProfile(profileId);
                deleteBtn.style.display = 'block';
                deleteBtn.dataset.profileId = profileId;
            } else {
                deleteBtn.style.display = 'none';
                delete deleteBtn.dataset.profileId;
            }
        });

        document.getElementById('deleteProfileBtn').addEventListener('click', (e) => {
            const profileId = e.target.dataset.profileId;
            if (profileId) {
                ProfileManager.deleteProfile(profileId);
                document.getElementById('profileSelect').value = '';
                e.target.style.display = 'none';
            }
        });

        document.getElementById('authTypeSelect').addEventListener('change', (e) => {
            ProfileManager.handleAuthTypeChange(e.target.value);
        });

        document.getElementById('jumpHostSelect').addEventListener('change', () => {
            if (window.JumpHostManager) {
                window.JumpHostManager.updatePasswordVisibility();
            }
        });

        document.getElementById('saveProfileCheck').addEventListener('change', (e) => {
            const profileNameGroup = document.getElementById('profileNameGroup');
            if (e.target.checked) {
                profileNameGroup.classList.remove('hidden');
                document.getElementById('profileNameInput').required = true;
            } else {
                profileNameGroup.classList.add('hidden');
                document.getElementById('profileNameInput').required = false;
            }
        });

        document.getElementById('manageKeysBtn').addEventListener('click', () => {
            window.ModalManager.open(document.getElementById('keyManagementModal'));
            ProfileManager.loadKeys();
        });

        document.getElementById('closeKeyModal').addEventListener('click', () => {
            window.ModalManager.close(document.getElementById('keyManagementModal'));
        });

        document.getElementById('keyUploadForm').addEventListener('submit', (e) => {
            e.preventDefault();

            const name = document.getElementById('keyNameInput').value;
            const keyContent = document.getElementById('keyContentInput').value;

            if (!name || !keyContent) {
                showNotification('Key name and content are required', 'error');
                return;
            }

            ProfileManager.uploadKey(name, keyContent);
        });

        document.getElementById('manageJumpHostsBtn')?.addEventListener('click', () => {
            window.ModalManager.open(document.getElementById('jumpHostManagementModal'));
            ProfileManager.loadKeys();
            if (window.JumpHostManager) {
                window.JumpHostManager.load();
                window.JumpHostManager.renderList();
            }
        });

        document.getElementById('closeJumpHostModal')?.addEventListener('click', () => {
            window.ModalManager.close(document.getElementById('jumpHostManagementModal'));
        });

        document.querySelectorAll('input[name="jhAuthType"]').forEach(radio => {
            radio.addEventListener('change', (e) => {
                document.getElementById('jhKeyGroup').classList.toggle('hidden', e.target.value !== 'key');
            });
        });

        document.getElementById('jumpHostForm')?.addEventListener('submit', (e) => {
            e.preventDefault();
            const name = document.getElementById('jhNameInput').value.trim();
            const host = document.getElementById('jhHostInput').value.trim();
            const port = document.getElementById('jhPortInput').value;
            const username = document.getElementById('jhUsernameInput').value.trim();
            const authType = document.querySelector('input[name="jhAuthType"]:checked').value;
            const keyId = document.getElementById('jhKeySelect').value;
            if (!name || !host || !username) {
                showNotification('Name, host and username are required', 'error');
                return;
            }
            if (authType === 'key' && !keyId) {
                showNotification('SSH key is required', 'error');
                return;
            }
            if (window.JumpHostManager) {
                window.JumpHostManager.save(name, host, port, username, authType, keyId);
            }
        });

        const changePasswordBtn = document.getElementById('changePasswordBtn');
        if (changePasswordBtn) {
            changePasswordBtn.addEventListener('click', () => {
                window.location.href = APP_ROOT + '/change-password';
            });
        }

        // Scrollback lines setting
        const scrollbackInput = document.getElementById('scrollbackInput');
        if (scrollbackInput) {
            const savedScrollback = localStorage.getItem('terminalScrollback') || '150';
            scrollbackInput.value = savedScrollback;
            scrollbackInput.addEventListener('change', () => {
                let val = parseInt(scrollbackInput.value, 10);
                if (isNaN(val) || val < 50) val = 50;
                if (val > 10000) val = 10000;
                scrollbackInput.value = val;
                localStorage.setItem('terminalScrollback', String(val));
                // Update all existing terminals
                Object.keys(TerminalManager.terminals).forEach(key => {
                    TerminalManager.terminals[key].options.scrollback = val;
                });
            });
        }

        document.getElementById('logoutBtn').addEventListener('click', () => {
            const message = window.i18n ? i18n.t('auth.logoutConfirm') : 'Are you sure you want to logout? Active SSH sessions will be preserved.';
            if (confirm(message)) {
                const form = document.createElement('form');
                form.method = 'POST';
                form.action = APP_ROOT + '/logout';
                const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
                if (csrfToken) {
                    const input = document.createElement('input');
                    input.type = 'hidden';
                    input.name = 'csrf_token';
                    input.value = csrfToken;
                    form.appendChild(input);
                }
                document.body.appendChild(form);
                form.submit();
            }
        });

        window.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal')) {
                window.ModalManager.close(e.target);
                if (e.target.id === 'connectionModal') {
                    clearPaneQueue();
                    if (connectTimer) { clearInterval(connectTimer); connectTimer = null; }
                }
            }
        });

        document.addEventListener('keydown', (e) => {
            const tag = document.activeElement?.tagName;
            if ((tag === 'INPUT' || tag === 'TEXTAREA') && e.key !== 'F1' && e.key !== 'Escape') {
                return;
            }

            if (e.key === 'F1') {
                e.preventDefault();
                CommandLibrary.openLibrary();
            }

            if (e.ctrlKey && e.key.toLowerCase() === 'f') {
                if (SessionManager.hasAnySessions()) {
                    e.preventDefault();
                    TerminalSearch.toggle();
                }
            }

            if (e.ctrlKey && e.key.toLowerCase() === 'k') {
                e.preventDefault();
                if (openPalette) {
                    openPalette();
                }
            }

            if (e.ctrlKey && (e.key === '/' || e.key === '?')) {
                e.preventDefault();
                if (openShortcuts) {
                    openShortcuts();
                }
            }

            if (e.ctrlKey && e.shiftKey && e.key === 'N') {
                e.preventDefault();
                document.getElementById('newConnectionBtn').click();
            }

            if (e.ctrlKey && !e.shiftKey && !e.altKey && e.key >= '1' && e.key <= '9') {
                e.preventDefault();
                const index = parseInt(e.key) - 1;
                const tabs = document.querySelectorAll('.session-tab');
                if (tabs[index]) {
                    tabs[index].click();
                }
            }

            if (e.ctrlKey && e.key === 'Tab') {
                e.preventDefault();
                const tabs = Array.from(document.querySelectorAll('.session-tab'));
                const activeIndex = tabs.findIndex(t => t.classList.contains('active'));
                if (tabs.length > 0) {
                    const nextIndex = e.shiftKey
                        ? (activeIndex - 1 + tabs.length) % tabs.length
                        : (activeIndex + 1) % tabs.length;
                    tabs[nextIndex].click();
                }
            }

            if (e.key === 'Escape') {
                if (TerminalSearch.isOpen) {
                    TerminalSearch.close();
                } else {
                    document.querySelectorAll('.modal.show').forEach(modal => {
                        window.ModalManager.close(modal);
                    });
                }
            }

            window.ModalManager.trapFocus(e);
        });

        document.getElementById('mobileMenuBtn').addEventListener('click', () => {
            document.querySelector('.header-buttons').classList.toggle('is-open');
        });

        document.addEventListener('click', (e) => {
            const menu = document.querySelector('.header-buttons');
            const menuBtn = document.getElementById('mobileMenuBtn');
            if (!menu || !menuBtn) {
                return;
            }
            if (!e.target.closest('.header-buttons') && e.target !== menuBtn) {
                menu.classList.remove('is-open');
            }
        });

        setupConnectionValidation();
        setupPasswordToggles();
        setupClipboardActions();
        setupDropUpload();
        setupSplitControls();
        setupNotepad();
        setupResizeHandle();
        TerminalSearch.init();
        FilePreview.init();

        shortcutsModal = setupShortcutsModal();
        openShortcuts = () => {
            if (shortcutsModal) {
                window.ModalManager.open(shortcutsModal);
            }
        };

        openPalette = setupCommandPalette();

        document.getElementById('closeCommandPaletteModal')?.addEventListener('click', () => {
            window.ModalManager.close(document.getElementById('commandPaletteModal'));
        });

        window.addEventListener('beforeunload', (e) => {
            const activeSessions = Object.values(SessionManager.sessions).filter(s => s.connected);
            if (activeSessions.length > 0) {
                const message = window.i18n
                    ? window.i18n.t('session.closeWarning', 'You have active SSH sessions. They will be closed.')
                    : 'You have active SSH sessions. They will be closed.';
                e.preventDefault();
                e.returnValue = message;
                return message;
            }
        });

        console.log('Web SSH Terminal initialized');
    });
})();
