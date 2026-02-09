// Main Application - Coordinates all components
(function() {
    'use strict';

    // Initialize Socket.IO connection
    window.socket = io();

    // SECURITY: HTML escaping utility to prevent XSS
    window.escapeHtml = function(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    };

    // Notification system
    window.showNotification = function(message, type = 'info', duration = 5000) {
        const container = document.getElementById('notificationContainer');
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.textContent = message;

        container.appendChild(notification);

        // Auto-remove after specified duration
        setTimeout(() => {
            notification.classList.add('fade-out');
            setTimeout(() => notification.remove(), 300);
        }, duration);
    };

    // Modal manager with focus trapping
    window.ModalManager = {
        activeModal: null,
        focusableSelector: 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',

        open(modal) {
            if (!modal) return;
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

    // Connection History (MRU - Most Recently Used)
    const ConnectionHistory = {
        maxItems: 10,
        storageKey: 'recentConnections',
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days in milliseconds

        getHistory() {
            try {
                const history = JSON.parse(localStorage.getItem(this.storageKey) || '[]');
                const now = Date.now();
                // Filter out entries older than 30 days
                const filtered = history.filter(entry => {
                    // Backwards compatibility: entries without timestamp are kept
                    if (!entry.timestamp) return true;
                    return (now - entry.timestamp) < this.maxAge;
                });
                // Save filtered history if anything was removed
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

            // Remove duplicate if exists
            const filtered = history.filter(h =>
                !(h.host === host && h.port === parseInt(port) && h.username === username)
            );

            // Add to beginning
            filtered.unshift(entry);

            // Keep only maxItems
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
                // SECURITY: Escape user-controlled data to prevent XSS
                option.innerHTML = `
                    <span class="recent-conn-label">${escapeHtml(conn.username)}@${escapeHtml(conn.host)}:${escapeHtml(String(conn.port))}</span>
                    <span class="recent-conn-time">${escapeHtml(this.formatTime(conn.timestamp))}</span>
                `;
                option.addEventListener('click', () => {
                    document.getElementById('hostInput').value = conn.host;
                    document.getElementById('portInput').value = conn.port;
                    document.getElementById('usernameInput').value = conn.username;
                    // Focus password field
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

    // Terminal Search Manager
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

            // Search on input
            this.searchInput.addEventListener('input', () => {
                this.performSearch();
            });

            // Keyboard navigation in search input
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

            // Button handlers
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

            // Clear search highlighting
            const activeSession = SessionManager.getActiveSession();
            if (activeSession) {
                TerminalManager.clearSearch(activeSession);
            }

            // Refocus terminal
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

    // File Preview Manager
    const FilePreview = {
        modal: null,
        currentSessionId: null,
        currentPath: null,

        // File type classifications
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

            // Close button
            document.getElementById('closeFilePreviewModal')?.addEventListener('click', () => this.close());

            // Click outside modal content to close
            this.modal.addEventListener('click', (e) => {
                if (e.target === this.modal) {
                    this.close();
                }
            });

            // Escape key to close
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape' && this.modal.classList.contains('show')) {
                    this.close();
                }
            });

            // Action buttons
            document.getElementById('previewCopyBtn')?.addEventListener('click', () => this.copyToClipboard());
            document.getElementById('previewDownloadBtn')?.addEventListener('click', () => this.downloadFile());
            document.getElementById('previewRefreshBtn')?.addEventListener('click', () => this.refresh());
            document.getElementById('previewBinaryDownload')?.addEventListener('click', () => this.downloadFile());

            // Socket event handlers
            socket.on('preview_data', (data) => {
                console.log('[FilePreview] preview_data received:', data);
                this.handlePreviewData(data);
            });
            socket.on('preview_error', (data) => {
                console.log('[FilePreview] preview_error received:', data);
                this.handlePreviewError(data);
            });
        },

        getFileType(filename) {
            const ext = '.' + filename.split('.').pop().toLowerCase();
            if (this.imageExtensions.includes(ext)) return 'image';
            if (this.logExtensions.includes(ext)) return 'log';
            if (this.codeExtensions.includes(ext)) return 'code';
            if (this.textExtensions.includes(ext)) return 'text';
            // Check for files without extensions that are likely text
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

            const fileType = this.getFileType(filename);
            console.log('[FilePreview] File type:', fileType);

            // Show modal and loading state
            this.showLoading();
            window.ModalManager.open(this.modal);

            // Set filename in header
            document.getElementById('previewFilename').textContent = filename;
            document.getElementById('previewSize').textContent = '';

            if (fileType === 'image') {
                // For images, download and display as base64
                console.log('[FilePreview] Loading image...');
                this.loadImage(sessionId, path, filename);
            } else {
                // For text/code files, use preview_file event
                const options = { session_id: sessionId, path: path };

                // For log files, use tail mode
                if (fileType === 'log') {
                    options.tail_lines = 1000;
                }

                console.log('[FilePreview] Emitting preview_file:', options);
                socket.emit('preview_file', options);
            }
        },

        loadImage(sessionId, path, filename) {
            // Use binary download for images with preview flag
            console.log('[FilePreview] Requesting image:', { sessionId, path, filename });
            socket.emit('download_file_binary', {
                session_id: sessionId,
                remote_path: path,
                for_preview: true  // Flag to distinguish from actual downloads
            });

            // Listen for binary download response
            const handleBinaryDownload = (data) => {
                // Only handle if this is a preview response
                if (!data.for_preview) return;

                console.log('[FilePreview] Received image data:', {
                    hasFileData: !!data.file_data,
                    encoding: data.encoding,
                    size: data.size,
                    filename: data.filename
                });

                socket.off('file_download_ready_binary', handleBinaryDownload);

                if (data.error) {
                    this.showError(data.error);
                    return;
                }

                try {
                    const mimeType = this.getMimeType(filename);
                    let url;

                    if (data.encoding === 'base64') {
                        // Create data URL from base64
                        url = `data:${mimeType};base64,${data.file_data}`;
                        console.log('[FilePreview] Created data URL from base64');
                    } else {
                        // Fallback: handle binary data
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
                        console.log('[FilePreview] Created blob URL:', url);
                    }

                    this.hideLoading();
                    this.showImage(url, data.size);
                } catch (err) {
                    console.error('[FilePreview] Error processing image:', err);
                    this.showError('Failed to display image: ' + err.message);
                }
            };

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

            // Update size info
            document.getElementById('previewSize').textContent = this.formatFileSize(data.size);

            if (data.is_binary) {
                this.showBinary();
                return;
            }

            // Show content
            this.showContent(data.content, data.filename, data.truncated, data.read_size, data.size);
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

            // Add load/error handlers
            imageElement.onload = () => {
                console.log('[FilePreview] Image loaded successfully');
            };
            imageElement.onerror = (e) => {
                console.error('[FilePreview] Image failed to load:', e);
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

            // Set content
            codeEl.textContent = content;

            // Apply syntax highlighting if available
            const language = this.getLanguage(filename);
            if (typeof hljs !== 'undefined') {
                codeEl.className = `language-${language}`;
                hljs.highlightElement(codeEl);
            }

            // Generate line numbers
            const lines = content.split('\n');
            lineNumbersEl.innerHTML = lines.map((_, i) => i + 1).join('<br>');

            // Show truncation warning if needed
            if (truncated) {
                document.getElementById('previewTruncated')?.classList.remove('hidden');
                document.getElementById('previewTruncatedSize').textContent = this.formatFileSize(readSize);
                document.getElementById('previewTotalSize').textContent = this.formatFileSize(totalSize);
            }
        },

        copyToClipboard() {
            const codeEl = document.getElementById('previewCode');
            if (!codeEl) return;

            navigator.clipboard.writeText(codeEl.textContent).then(() => {
                showNotification('Copied to clipboard', 'success');
            }).catch(() => {
                showNotification('Failed to copy', 'error');
            });
        },

        downloadFile() {
            if (!this.currentSessionId || !this.currentPath) return;

            // Trigger download via existing download mechanism
            socket.emit('download_file_binary', {
                session_id: this.currentSessionId,
                remote_path: this.currentPath
            });
        },

        refresh() {
            if (!this.currentSessionId || !this.currentPath) return;

            const filename = this.currentPath.split('/').pop();
            this.open(this.currentSessionId, this.currentPath, filename);
        },

        close() {
            window.ModalManager.close(this.modal);
            this.currentSessionId = null;
            this.currentPath = null;

            // Clean up image blob URL
            const imgEl = document.getElementById('previewImageElement');
            if (imgEl && imgEl.src.startsWith('blob:')) {
                URL.revokeObjectURL(imgEl.src);
                imgEl.src = '';
            }
        }
    };

    window.FilePreview = FilePreview;

    // Socket.IO Event Handlers
    socket.on('connect', () => {
        console.log('Connected to server');
        const reconnectBar = document.getElementById('reconnectBar');
        if (reconnectBar && reconnectBar.style.display !== 'none') {
            reconnectBar.style.display = 'none';
            showNotification('Reconnected!', 'success', 2000);
        }
    });

    // Keep-alive to prevent session timeout
    setInterval(() => {
        if (socket.connected) {
            socket.emit('keep_alive');
        }
    }, 60000);

    // Reconnect attempt handler
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
    });

    socket.on('ssh_connected', (data) => {
        console.log('SSH connected:', data);

        if (data.client_request_id) {
            SessionManager.clearPendingConnection(data.client_request_id);
        }

        // Stop connection timer
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

        // Create session
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

        // Prompt the shell to render immediately
        setTimeout(() => {
            socket.emit('ssh_input', {
                session_id: sessionId,
                data: '\n'
            });
        }, 200);

        // Close connection modal
        window.ModalManager.close(document.getElementById('connectionModal'));
        processPaneQueue();

        showNotification(`Connected to ${data.username}@${data.host}`, 'success');

        // Add to connection history
        ConnectionHistory.addConnection(data.host, data.port, data.username);

        // Update file transfer session selects
        FileTransferManager.updateSessionSelects();
    });

    socket.on('ssh_output', (data) => {
        console.log(`[SSH_OUTPUT] Received for session ${data.session_id}, length: ${data.data.length}`);
        TerminalManager.writeOutput(data.session_id, data.data);

        // OS detection disabled.
    });

    socket.on('ssh_error', (data) => {
        console.error('SSH error:', data);
        showNotification(`SSH Error: ${data.error}`, 'error');

        // Stop connection timer
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
        showNotification(`Error: ${data.error}`, 'error');
    });

    socket.on('notepad_data', (data) => {
        const notepad = document.getElementById('sessionNotepad');
        if (!notepad) {
            return;
        }
        notepad.value = (data && data.notepad) ? data.notepad : '';
    });

    // UI Event Handlers
    let currentConnectRequestId = null;
    let pendingPaneIndex = null;
    const pendingPaneQueue = [];
    const pendingRequestPaneMap = new Map();
    let connectTimer = null;
    let connectSeconds = 0;

    function openConnectionModalForPane(paneIndex) {
        pendingPaneIndex = paneIndex;
        if (paneIndex !== null && paneIndex !== undefined) {
            SessionManager.setActivePane(paneIndex);
        }

        // Render connection history
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
        const authRadios = document.querySelectorAll('input[name="authType"]');

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

        authRadios.forEach(radio => {
            radio.addEventListener('change', () => {
                if (radio.value === 'password' && passwordInput) {
                    setFieldState(passwordInput, passHint, passwordInput.value ? '✓ Ready' : 'Password required', Boolean(passwordInput.value));
                }
                if (radio.value === 'key' && keySelect) {
                    setFieldState(keySelect, keyHint, keySelect.value ? '✓ Key selected' : 'Select a key', Boolean(keySelect.value));
                }
            });
        });
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

    }

    function setupSplitControls() {
        document.querySelectorAll('.split-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const layout = parseInt(btn.dataset.layout, 10);
                const currentLayout = SessionManager.layout;

                // If changing layout and we have sessions, show assignment modal
                if (layout !== currentLayout && SessionManager.hasAnySessions()) {
                    SessionManager.showPaneAssignmentModal(layout);
                } else {
                    // No sessions yet, just change layout directly
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
                // Auto-hide after 2 seconds
                setTimeout(() => {
                    saveStatus.className = 'notepad-save-status';
                    saveStatus.textContent = '';
                }, 2000);
            }
        };

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
            isResizing = true;
            // Support both mouse and touch via pointer events
            startX = e.clientX ?? e.touches?.[0]?.clientX ?? 0;
            startNotepadWidth = notepadPanel.offsetWidth;

            document.body.style.cursor = 'col-resize';
            document.body.style.userSelect = 'none';

            // Capture pointer for reliable tracking
            if (e.pointerId !== undefined) {
                handle.setPointerCapture(e.pointerId);
            }

            e.preventDefault();
        };

        const resize = (e) => {
            if (!isResizing) {
                return;
            }

            // Support both mouse and touch via pointer events
            const clientX = e.clientX ?? e.touches?.[0]?.clientX ?? 0;
            const deltaX = clientX - startX;
            const workspaceWidth = workspace.offsetWidth;

            // Calculate new widths
            let newNotepadWidth = startNotepadWidth - deltaX;

            // Apply constraints
            const minNotepadWidth = 180;
            const maxNotepadWidth = workspaceWidth * 0.6;
            const minTerminalWidth = workspaceWidth * 0.3;

            newNotepadWidth = Math.max(minNotepadWidth, Math.min(maxNotepadWidth, newNotepadWidth));
            let newTerminalWidth = workspaceWidth - newNotepadWidth;

            if (newTerminalWidth < minTerminalWidth) {
                newTerminalWidth = minTerminalWidth;
                newNotepadWidth = workspaceWidth - minTerminalWidth;
            }

            // Apply the new layout
            workspace.style.setProperty('--notepad-width', `${newNotepadWidth}px`);

            // Trigger terminal resize
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

            // Save the current layout
            const notepadWidth = notepadPanel.getBoundingClientRect().width;
            if (!Number.isNaN(notepadWidth) && notepadWidth > 0) {
                saveLayout(notepadWidth);
            }
        };

        // Use pointer events for combined mouse + touch support
        handle.addEventListener('pointerdown', startResize);
        document.addEventListener('pointermove', resize);
        document.addEventListener('pointerup', stopResize);
        document.addEventListener('pointercancel', stopResize);

        // Prevent default touch behavior on handle for smoother dragging
        handle.style.touchAction = 'none';

        // Load saved layout on init
        loadLayout();

        // Notepad collapse toggle
        const notepadToggle = document.getElementById('notepadToggle');
        if (notepadToggle && notepadPanel) {
            // Restore collapsed state
            if (localStorage.getItem('notepadCollapsed') === 'true') {
                notepadPanel.classList.add('collapsed');
                notepadToggle.textContent = '▶';
            }
            notepadToggle.addEventListener('click', () => {
                notepadPanel.classList.toggle('collapsed');
                const isCollapsed = notepadPanel.classList.contains('collapsed');
                notepadToggle.textContent = isCollapsed ? '▶' : '◀';
                localStorage.setItem('notepadCollapsed', isCollapsed);
                // Trigger terminal refit after animation
                setTimeout(() => {
                    if (window.TerminalManager) {
                        TerminalManager.fitAllTerminals();
                    }
                }, 300);
            });
        }

        // Double-click to reset to default
        handle.addEventListener('dblclick', () => {
            workspace.style.removeProperty('--notepad-width');
            localStorage.removeItem('workspace-notepad-width');
            showNotification('Layout reset to default', 'info');

            // Trigger terminal resize
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
        // Create reconnect bar (once, at init)
        const reconnectBar = document.createElement('div');
        reconnectBar.id = 'reconnectBar';
        reconnectBar.className = 'reconnect-bar';
        reconnectBar.style.display = 'none';
        reconnectBar.innerHTML = '<span class="reconnect-text">Connection lost. Reconnecting...</span>';
        const header = document.querySelector('.header');
        if (header) {
            header.after(reconnectBar);
        }

        // Initialize SessionManager for session restore
        SessionManager.init();

        // Initialize Command Library
        CommandLibrary.init();

        // Load profiles and keys on startup
        ProfileManager.loadProfiles();
        ProfileManager.loadKeys();

        // New Connection Button
        document.getElementById('newConnectionBtn').addEventListener('click', () => {
            openConnectionModalForPane(getDefaultPaneIndex());
        });

        // Close Connection Modal
        document.getElementById('closeConnectionModal').addEventListener('click', () => {
            window.ModalManager.close(document.getElementById('connectionModal'));
            setConnectLoading(false);
            currentConnectRequestId = null;
            clearPaneQueue();
        });

        document.getElementById('cancelConnectionBtn').addEventListener('click', () => {
            window.ModalManager.close(document.getElementById('connectionModal'));
            setConnectLoading(false);
            currentConnectRequestId = null;
            clearPaneQueue();
        });

        // Connection Form Submit
        document.getElementById('connectionForm').addEventListener('submit', (e) => {
            e.preventDefault();

            const host = document.getElementById('hostInput').value;
            const port = document.getElementById('portInput').value;
            const username = document.getElementById('usernameInput').value;
            const authType = document.querySelector('input[name="authType"]:checked').value;
            const password = document.getElementById('passwordInput').value;
            const keyId = document.getElementById('keySelect').value;
            const saveProfile = document.getElementById('saveProfileCheck').checked;
            const profileName = document.getElementById('profileNameInput').value;
            const targetPane = pendingPaneIndex;
            pendingPaneIndex = null;

            // Validate
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

            // Save profile if requested
            if (saveProfile && profileName) {
                ProfileManager.saveProfile({
                    name: profileName,
                    host: host,
                    port: parseInt(port),
                    username: username,
                    auth_type: authType,
                    key_id: authType === 'key' ? keyId : null
                });
            }

            // Connect to SSH
            currentConnectRequestId = `req_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`;
            SessionManager.createPendingConnection(currentConnectRequestId, host, username, port);
            if (targetPane !== null && targetPane !== undefined) {
                pendingRequestPaneMap.set(currentConnectRequestId, targetPane);
            }

            const connectionData = {
                host: host,
                port: parseInt(port),
                username: username,
                client_request_id: currentConnectRequestId
            };

            if (authType === 'password') {
                connectionData.password = password;
            } else {
                connectionData.key_id = keyId;
            }

            // Start connection timer feedback
            const connectBtn = document.getElementById('connectBtn');
            const originalText = connectBtn.textContent;
            connectSeconds = 0;
            connectBtn.textContent = 'Connecting... 0s';
            connectTimer = setInterval(() => {
                connectSeconds++;
                connectBtn.textContent = `Connecting... ${connectSeconds}s`;
            }, 1000);

            socket.emit('ssh_connect', connectionData);
            setConnectLoading(true);

            // Clear password field for security
            document.getElementById('passwordInput').value = '';
        });

        // Profile Selection
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

        // Delete Profile Button
        document.getElementById('deleteProfileBtn').addEventListener('click', (e) => {
            const profileId = e.target.dataset.profileId;
            if (profileId) {
                ProfileManager.deleteProfile(profileId);
                // Reset form after deletion
                document.getElementById('profileSelect').value = '';
                e.target.style.display = 'none';
            }
        });

        // Auth Type Change
        document.querySelectorAll('input[name="authType"]').forEach(radio => {
            radio.addEventListener('change', (e) => {
                ProfileManager.handleAuthTypeChange(e.target.value);
            });
        });

        // Save Profile Checkbox
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

        // Manage Keys Button
        document.getElementById('manageKeysBtn').addEventListener('click', () => {
            window.ModalManager.open(document.getElementById('keyManagementModal'));
            ProfileManager.loadKeys();
        });

        // Close Key Management Modal
        document.getElementById('closeKeyModal').addEventListener('click', () => {
            window.ModalManager.close(document.getElementById('keyManagementModal'));
        });

        // Key Upload Form
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

        // File Transfer Button - Now handled by openFileManager() in sftp-file-manager.js
        // The onclick handler is set directly in HTML: onclick="openFileManager()"
        // Old modal code removed - we now use the new dual-pane file manager

        // Change Password Button
        const changePasswordBtn = document.getElementById('changePasswordBtn');
        if (changePasswordBtn) {
            changePasswordBtn.addEventListener('click', () => {
                window.location.href = '/change-password';
            });
        }

        // Old File Transfer Modal handlers removed - using new dual-pane file manager
        // Legacy upload/download forms no longer needed

        // Logout Button
        document.getElementById('logoutBtn').addEventListener('click', () => {
            const message = window.i18n ? i18n.t('auth.logoutConfirm') : 'Are you sure you want to logout? Active SSH sessions will be preserved.';
            if (confirm(message)) {
                const form = document.createElement('form');
                form.method = 'POST';
                form.action = '/logout';
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

        // Close modals when clicking outside
        window.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal')) {
                window.ModalManager.close(e.target);
                if (e.target.id === 'connectionModal') {
                    clearPaneQueue();
                }
            }
        });

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            // Skip shortcuts when typing in form inputs (except F1/Escape)
            const tag = document.activeElement?.tagName;
            if ((tag === 'INPUT' || tag === 'TEXTAREA') && e.key !== 'F1' && e.key !== 'Escape') {
                return;
            }

            // F1: Open Command Library
            if (e.key === 'F1') {
                e.preventDefault();
                CommandLibrary.openLibrary();
            }

            // Ctrl+F: Terminal Search
            if (e.ctrlKey && e.key.toLowerCase() === 'f') {
                // Only intercept if there's an active terminal session
                if (SessionManager.hasAnySessions()) {
                    e.preventDefault();
                    TerminalSearch.toggle();
                }
            }

            // Ctrl+K: Command Palette
            if (e.ctrlKey && e.key.toLowerCase() === 'k') {
                e.preventDefault();
                if (openPalette) {
                    openPalette();
                }
            }

            // Ctrl+?: Shortcuts help
            if (e.ctrlKey && (e.key === '/' || e.key === '?')) {
                e.preventDefault();
                if (openShortcuts) {
                    openShortcuts();
                }
            }

            // Ctrl+Shift+N: New Connection
            if (e.ctrlKey && e.shiftKey && e.key === 'N') {
                e.preventDefault();
                document.getElementById('newConnectionBtn').click();
            }

            // Ctrl+1-9: Switch to tab by index
            if (e.ctrlKey && !e.shiftKey && !e.altKey && e.key >= '1' && e.key <= '9') {
                e.preventDefault();
                const index = parseInt(e.key) - 1;
                const tabs = document.querySelectorAll('.session-tab');
                if (tabs[index]) {
                    tabs[index].click();
                }
            }

            // Ctrl+Tab / Ctrl+Shift+Tab: Next/Previous tab
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

            // Escape: Close modals and search bar
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

        // Warning when closing with active sessions
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
