/**
 * SFTP Multi-Host File Manager
 * Dual-pane file manager where BOTH panes can display:
 * - Browser Local (user's computer via File System Access API)
 * - SSH Remote (via active terminal sessions or quick connect)
 *
 * Supports direct server-to-server transfers without local intermediate.
 */

class SFTPFileManager {
    constructor() {
        this.socket = window.socket;
        this.modal = null;
        this.isOpen = false;

        // Browser File System (for "Your Computer" access)
        this.browserFS = new BrowserFileSystem();

        // Symmetric Pane State
        this.panes = {
            left: this.createEmptyPaneState(),
            right: this.createEmptyPaneState()
        };
        this.activePane = 'left';

        // Available connections
        this.availableSessions = [];  // Terminal sessions
        this.quickConnections = [];   // Quick connect sessions

        // Transfer queue
        this.transferQueue = [];
        this.activeTransfers = new Map();
        this.isTransferring = false;

        // Conflict handling
        this.conflictAction = null;
        this.applyToAll = false;

        // Context menu
        this.contextMenu = null;

        // Drag state
        this.draggedItems = [];
        this.dragSource = null;

        // Initialize
        this.init();
    }

    createEmptyPaneState() {
        return {
            type: null,              // 'browser-local' | 'ssh'
            sessionId: null,         // For SSH terminal sessions
            connectionId: null,      // For Quick Connect
            path: '/',
            files: [],
            selected: new Set(),
            lastSelected: -1,
            hostInfo: null,          // { host, username, port }
            loading: false,
            loadingTimeout: null,    // Timeout ID for loading state
            error: null              // Error message if loading failed
        };
    }

    init() {
        this.createModal();
        this.setupSocketListeners();
        this.setupKeyboardShortcuts();
    }

    // ==================== MODAL CREATION ====================

    createModal() {
        const modal = document.createElement('div');
        modal.id = 'sftpFileManager';
        modal.className = 'modal';
        modal.innerHTML = `
            <div class="modal-content fm-modal-fullwidth">
                <div class="modal-header">
                    <h2><span class="material-icons">folder_open</span> <span data-i18n="fm.title">File Manager</span></h2>
                    <span class="close" id="fmClose">&times;</span>
                </div>
                <div class="modal-body">
                    <!-- Toolbar -->
                    <div class="fm-toolbar">
                        <div class="fm-toolbar-left">
                            <button class="btn btn-secondary btn-sm" id="fmRefresh" data-i18n-title="fm.refresh">
                                <span class="material-icons">refresh</span>
                            </button>
                            <button class="btn btn-secondary btn-sm" id="fmNewFolder" data-i18n-title="fm.newFolder">
                                <span class="material-icons">create_new_folder</span>
                                <span class="btn-text" data-i18n="fm.newFolder">New Folder</span>
                            </button>
                        </div>
                        <div class="fm-toolbar-center">
                            <button class="btn btn-primary btn-sm" id="fmTransfer" data-i18n-title="fm.transfer">
                                <span class="material-icons">swap_horiz</span>
                                <span class="btn-text" data-i18n="fm.transfer">Transfer</span>
                            </button>
                        </div>
                        <div class="fm-toolbar-right">
                            <button class="btn btn-secondary btn-sm" id="fmDownload" data-i18n-title="fm.download">
                                <span class="material-icons">download</span>
                            </button>
                            <button class="btn btn-secondary btn-sm" id="fmRename" data-i18n-title="fm.rename">
                                <span class="material-icons">edit</span>
                            </button>
                            <button class="btn btn-danger btn-sm" id="fmDelete" data-i18n-title="fm.delete">
                                <span class="material-icons">delete</span>
                            </button>
                        </div>
                    </div>

                    <!-- Mobile Pane Tabs -->
                    <div class="fm-pane-tabs" id="fmPaneTabs">
                        <button class="fm-pane-tab active" data-pane="left">
                            <span class="material-icons">folder</span> Left
                        </button>
                        <button class="fm-pane-tab" data-pane="right">
                            <span class="material-icons">folder</span> Right
                        </button>
                    </div>

                    <!-- Dual Pane -->
                    <div class="fm-panes">
                        <!-- Left Pane -->
                        <div class="fm-pane active" id="fmLeftPane" data-pane="left">
                            <div class="fm-pane-header">
                                <select class="fm-source-select form-control" id="fmLeftSource">
                                    <option value="" data-i18n="fm.selectSource">-- Select Source --</option>
                                    <optgroup data-i18n-label="fm.sshSessions" label="SSH Sessions" id="fmLeftSessions"></optgroup>
                                    <option value="quick-connect" data-i18n="fm.newConnection">+ New Connection...</option>
                                </select>
                            </div>
                            <div class="fm-pane-nav">
                                <button class="fm-nav-btn" id="fmLeftUp" data-i18n-title="fm.goUp">
                                    <span class="material-icons">arrow_upward</span>
                                </button>
                                <button class="fm-nav-btn" id="fmLeftHome" data-i18n-title="fm.goHome">
                                    <span class="material-icons">home</span>
                                </button>
                                <div class="fm-breadcrumb" id="fmLeftBreadcrumb">
                                    <input type="text" class="fm-path-input" id="fmLeftPath" value="/" placeholder="/path">
                                </div>
                                <button class="fm-nav-btn" id="fmLeftRefresh" data-i18n-title="fm.refresh">
                                    <span class="material-icons">refresh</span>
                                </button>
                            </div>
                            <div class="fm-file-list" id="fmLeftList">
                                <div class="fm-empty">
                                    <span class="material-icons fm-empty-icon">folder_open</span>
                                    <div class="fm-empty-text" data-i18n="fm.selectSourceAbove">Select a source above</div>
                                </div>
                            </div>
                            <div class="fm-pane-footer">
                                <span class="fm-host-badge" id="fmLeftBadge"></span>
                                <div class="fm-pane-status">
                                    <span id="fmLeftCount">0 items</span>
                                    <span id="fmLeftSelected"></span>
                                </div>
                            </div>
                        </div>

                        <!-- Right Pane -->
                        <div class="fm-pane" id="fmRightPane" data-pane="right">
                            <div class="fm-pane-header">
                                <select class="fm-source-select form-control" id="fmRightSource">
                                    <option value="" data-i18n="fm.selectSource">-- Select Source --</option>
                                    <optgroup data-i18n-label="fm.sshSessions" label="SSH Sessions" id="fmRightSessions"></optgroup>
                                    <option value="quick-connect" data-i18n="fm.newConnection">+ New Connection...</option>
                                </select>
                            </div>
                            <div class="fm-pane-nav">
                                <button class="fm-nav-btn" id="fmRightUp" data-i18n-title="fm.goUp">
                                    <span class="material-icons">arrow_upward</span>
                                </button>
                                <button class="fm-nav-btn" id="fmRightHome" data-i18n-title="fm.goHome">
                                    <span class="material-icons">home</span>
                                </button>
                                <div class="fm-breadcrumb" id="fmRightBreadcrumb">
                                    <input type="text" class="fm-path-input" id="fmRightPath" value="/" placeholder="/path">
                                </div>
                                <button class="fm-nav-btn" id="fmRightRefresh" data-i18n-title="fm.refresh">
                                    <span class="material-icons">refresh</span>
                                </button>
                            </div>
                            <div class="fm-file-list" id="fmRightList">
                                <div class="fm-empty">
                                    <span class="material-icons fm-empty-icon">folder_open</span>
                                    <div class="fm-empty-text" data-i18n="fm.selectSourceAbove">Select a source above</div>
                                </div>
                            </div>
                            <div class="fm-pane-footer">
                                <span class="fm-host-badge" id="fmRightBadge"></span>
                                <div class="fm-pane-status">
                                    <span id="fmRightCount">0 items</span>
                                    <span id="fmRightSelected"></span>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Transfer Queue -->
                    <div class="fm-queue" id="fmQueue">
                        <div class="fm-queue-header" id="fmQueueHeader">
                            <div class="fm-queue-title">
                                <span class="material-icons">sync</span>
                                <span data-i18n="fm.transfers">Transfers</span> <span class="fm-queue-badge" id="fmQueueBadge">0</span>
                            </div>
                            <span class="fm-queue-toggle material-icons" id="fmQueueToggle">expand_more</span>
                        </div>
                        <div class="fm-queue-list" id="fmQueueList"></div>
                    </div>

                    <!-- Mobile Upload Button -->
                    <div class="fm-mobile-upload" id="fmMobileUpload">
                        <span class="material-icons">cloud_upload</span>
                        <span>Tap to upload files</span>
                        <input type="file" id="fmMobileUploadInput" multiple hidden>
                    </div>
                </div>

                <!-- Mobile Action Sheet -->
                <div class="fm-action-sheet" id="fmActionSheet">
                    <div class="fm-action-sheet-item" data-action="open">
                        <span class="material-icons">folder_open</span>
                        <span>Open</span>
                    </div>
                    <div class="fm-action-sheet-item" data-action="download">
                        <span class="material-icons">download</span>
                        <span>Download</span>
                    </div>
                    <div class="fm-action-sheet-item" data-action="transfer">
                        <span class="material-icons">swap_horiz</span>
                        <span>Transfer</span>
                    </div>
                    <div class="fm-action-sheet-item" data-action="rename">
                        <span class="material-icons">edit</span>
                        <span>Rename</span>
                    </div>
                    <div class="fm-action-sheet-item" data-action="newfolder">
                        <span class="material-icons">create_new_folder</span>
                        <span>New Folder</span>
                    </div>
                    <div class="fm-action-sheet-item danger" data-action="delete">
                        <span class="material-icons">delete</span>
                        <span>Delete</span>
                    </div>
                    <div class="fm-action-sheet-cancel fm-action-sheet-item" data-action="cancel">
                        <span class="material-icons">close</span>
                        <span>Cancel</span>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
        this.modal = modal;

        // Quick Connect Modal
        this.createQuickConnectModal();

        this.setupEventListeners();
    }

    createQuickConnectModal() {
        const qcModal = document.createElement('div');
        qcModal.id = 'fmQuickConnectModal';
        qcModal.className = 'modal';
        qcModal.innerHTML = `
            <div class="modal-content fm-qc-modal">
                <div class="modal-header">
                    <h2 data-i18n="fm.qc.title">Connect to Server</h2>
                    <span class="close" id="fmQcClose">&times;</span>
                </div>
                <div class="modal-body">
                    <form id="fmQcForm">
                        <!-- Profile Selector -->
                        <div class="form-group">
                            <label for="fmQcProfile" data-i18n="fm.qc.savedProfiles">Saved Profiles</label>
                            <select id="fmQcProfile" class="form-control">
                                <option value="" data-i18n="fm.qc.enterManually">-- Enter manually --</option>
                            </select>
                        </div>

                        <div class="fm-qc-divider">
                            <span data-i18n="fm.qc.orEnterDetails">or enter connection details</span>
                        </div>

                        <div class="form-row">
                            <div class="form-group flex-2">
                                <label for="fmQcHost" data-i18n="fm.qc.host">Host</label>
                                <input type="text" id="fmQcHost" class="form-control" placeholder="hostname or IP" required>
                            </div>
                            <div class="form-group flex-1">
                                <label for="fmQcPort" data-i18n="fm.qc.port">Port</label>
                                <input type="number" id="fmQcPort" class="form-control" value="22" min="1" max="65535">
                            </div>
                        </div>

                        <div class="form-group">
                            <label for="fmQcUsername" data-i18n="fm.qc.username">Username</label>
                            <input type="text" id="fmQcUsername" class="form-control" required>
                        </div>

                        <div class="form-group">
                            <label data-i18n="fm.qc.authentication">Authentication</label>
                            <div class="auth-type-selector">
                                <label class="radio-label">
                                    <input type="radio" name="fmQcAuth" value="password" checked>
                                    <span data-i18n="fm.qc.password">Password</span>
                                </label>
                                <label class="radio-label">
                                    <input type="radio" name="fmQcAuth" value="key">
                                    <span data-i18n="fm.qc.sshKey">SSH Key</span>
                                </label>
                            </div>
                        </div>

                        <div class="form-group" id="fmQcPasswordGroup">
                            <label for="fmQcPassword" data-i18n="fm.qc.password">Password</label>
                            <div class="input-wrapper with-toggle">
                                <input type="password" id="fmQcPassword" class="form-control" placeholder="Enter password">
                                <button type="button" class="password-toggle" id="fmQcPwToggle" aria-label="Toggle password visibility">
                                    <span class="material-icons">visibility</span>
                                </button>
                            </div>
                        </div>

                        <div class="form-group hidden" id="fmQcKeyGroup">
                            <label for="fmQcKeySelect" data-i18n="fm.qc.sshKey">SSH Key</label>
                            <select id="fmQcKeySelect" class="form-control">
                                <option value="" data-i18n="fm.qc.selectKey">-- Select Key --</option>
                            </select>
                        </div>

                        <div class="form-actions">
                            <button type="button" class="btn btn-secondary" id="fmQcCancel" data-i18n="common.cancel">Cancel</button>
                            <button type="submit" class="btn btn-primary" id="fmQcConnectBtn">
                                <span class="btn-label" data-i18n="fm.qc.connect">Connect</span>
                                <span class="btn-spinner hidden"></span>
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        `;
        document.body.appendChild(qcModal);
        this.qcModal = qcModal;
        this.pendingQuickConnectPane = null;

        // Quick Connect event listeners
        document.getElementById('fmQcClose').addEventListener('click', () => this.closeQuickConnect());
        document.getElementById('fmQcCancel').addEventListener('click', () => this.closeQuickConnect());
        qcModal.addEventListener('click', (e) => {
            if (e.target === qcModal) this.closeQuickConnect();
        });

        // Profile selector - auto-fill form when profile selected
        document.getElementById('fmQcProfile').addEventListener('change', (e) => {
            this.onProfileSelect(e.target.value);
        });

        // Password visibility toggle
        document.getElementById('fmQcPwToggle').addEventListener('click', () => {
            const pwInput = document.getElementById('fmQcPassword');
            const icon = document.querySelector('#fmQcPwToggle .material-icons');
            if (pwInput.type === 'password') {
                pwInput.type = 'text';
                icon.textContent = 'visibility_off';
            } else {
                pwInput.type = 'password';
                icon.textContent = 'visibility';
            }
        });

        // Auth type toggle
        qcModal.querySelectorAll('input[name="fmQcAuth"]').forEach(radio => {
            radio.addEventListener('change', (e) => {
                document.getElementById('fmQcPasswordGroup').classList.toggle('hidden', e.target.value !== 'password');
                document.getElementById('fmQcKeyGroup').classList.toggle('hidden', e.target.value !== 'key');
            });
        });

        // Form submit
        document.getElementById('fmQcForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.submitQuickConnect();
        });
    }

    // ==================== EVENT LISTENERS ====================

    setupEventListeners() {
        // Close modal
        document.getElementById('fmClose').addEventListener('click', () => this.close());
        this.modal.addEventListener('click', (e) => {
            if (e.target === this.modal) this.close();
        });

        // Toolbar
        document.getElementById('fmRefresh').addEventListener('click', () => this.refreshBothPanes());
        document.getElementById('fmNewFolder').addEventListener('click', () => this.createNewFolder());
        document.getElementById('fmTransfer').addEventListener('click', () => this.executeTransfer());
        document.getElementById('fmDownload').addEventListener('click', () => this.downloadSelected());
        document.getElementById('fmRename').addEventListener('click', () => this.renameSelected());
        document.getElementById('fmDelete').addEventListener('click', () => this.deleteSelected());

        // Left Pane
        document.getElementById('fmLeftSource').addEventListener('change', (e) => this.onSourceChange('left', e.target.value));
        document.getElementById('fmLeftUp').addEventListener('click', () => this.navigatePaneUp('left'));
        document.getElementById('fmLeftHome').addEventListener('click', () => this.navigatePaneHome('left'));
        document.getElementById('fmLeftRefresh').addEventListener('click', () => this.refreshPane('left'));
        document.getElementById('fmLeftPath').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.navigatePaneTo('left', e.target.value);
        });
        document.getElementById('fmLeftPane').addEventListener('click', (e) => {
            if (!e.target.closest('.fm-file-item') && !e.target.closest('.fm-pane-header') && !e.target.closest('.fm-pane-nav')) {
                this.setActivePane('left');
            }
        });

        // Right Pane
        document.getElementById('fmRightSource').addEventListener('change', (e) => this.onSourceChange('right', e.target.value));
        document.getElementById('fmRightUp').addEventListener('click', () => this.navigatePaneUp('right'));
        document.getElementById('fmRightHome').addEventListener('click', () => this.navigatePaneHome('right'));
        document.getElementById('fmRightRefresh').addEventListener('click', () => this.refreshPane('right'));
        document.getElementById('fmRightPath').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.navigatePaneTo('right', e.target.value);
        });
        document.getElementById('fmRightPane').addEventListener('click', (e) => {
            if (!e.target.closest('.fm-file-item') && !e.target.closest('.fm-pane-header') && !e.target.closest('.fm-pane-nav')) {
                this.setActivePane('right');
            }
        });

        // Drop zones
        this.setupDropZones();

        // Queue toggle
        document.getElementById('fmQueueHeader').addEventListener('click', () => this.toggleQueue());

        // Context menu close
        document.addEventListener('click', () => this.closeContextMenu());

        // Mobile: Pane tabs
        document.querySelectorAll('.fm-pane-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                const pane = e.currentTarget.dataset.pane;
                this.setActivePane(pane);
                this.updateMobilePaneTabs(pane);
            });
        });

        // Mobile: Upload button
        const mobileUpload = document.getElementById('fmMobileUpload');
        const mobileUploadInput = document.getElementById('fmMobileUploadInput');
        if (mobileUpload && mobileUploadInput) {
            mobileUpload.addEventListener('click', () => mobileUploadInput.click());
            mobileUploadInput.addEventListener('change', (e) => this.handleMobileUpload(e));
        }

        // Mobile: Action sheet
        document.querySelectorAll('.fm-action-sheet-item').forEach(item => {
            item.addEventListener('click', (e) => {
                const action = e.currentTarget.dataset.action;
                this.handleActionSheetAction(action);
            });
        });

        // Mobile: Long press for action sheet
        this.setupLongPress();
    }

    setupDropZones() {
        ['left', 'right'].forEach(pane => {
            const paneEl = document.getElementById(`fm${this.capitalize(pane)}Pane`);

            paneEl.addEventListener('dragenter', (e) => {
                // Hide global drag-drop overlay when dragging over file manager
                if (window.dragDropManager && e.dataTransfer?.types?.includes('Files')) {
                    window.dragDropManager.dragCounter = 0;
                    window.dragDropManager.hideOverlay();
                }
            });

            paneEl.addEventListener('dragover', (e) => {
                e.preventDefault();
                e.stopPropagation();
                // Show drop target if dragging from other pane
                if (this.dragSource && this.dragSource !== pane) {
                    paneEl.classList.add('drop-target');
                }
                // Also allow dropping files from desktop
                if (e.dataTransfer?.types?.includes('Files')) {
                    paneEl.classList.add('drop-target');
                }
            });

            paneEl.addEventListener('dragleave', (e) => {
                if (!paneEl.contains(e.relatedTarget)) {
                    paneEl.classList.remove('drop-target');
                }
            });

            paneEl.addEventListener('drop', (e) => {
                e.preventDefault();
                e.stopPropagation();
                paneEl.classList.remove('drop-target');
                this.handleDrop(e, pane);

                // Reset global drag counter to hide overlay
                if (window.dragDropManager) {
                    window.dragDropManager.dragCounter = 0;
                    window.dragDropManager.hideOverlay();
                }
            });
        });
    }

    setupSocketListeners() {
        if (!this.socket) return;

        // ==================== SSH DIRECTORY LISTING ====================

        this.socket.on('directory_listing', (data) => {
            if (!this.isOpen) return;

            // Find which pane requested this
            ['left', 'right'].forEach(pane => {
                const state = this.panes[pane];
                if (state.type === 'ssh' &&
                    (state.sessionId === data.session_id || state.connectionId === data.session_id)) {
                    // Clear loading timeout
                    if (state.loadingTimeout) {
                        clearTimeout(state.loadingTimeout);
                        state.loadingTimeout = null;
                    }
                    state.files = data.files || [];
                    state.path = data.path;
                    state.loading = false;
                    state.error = null;
                    this.updatePathInput(pane, data.path);
                    this.renderPane(pane);
                }
            });
        });

        this.socket.on('home_directory', (data) => {
            ['left', 'right'].forEach(pane => {
                const state = this.panes[pane];
                if (state.type === 'ssh' &&
                    (state.sessionId === data.session_id || state.connectionId === data.session_id)) {
                    if (!state.homePath) {
                        state.homePath = data.path;
                        // Navigate to home on first load
                        if (state.path === '/') {
                            this.navigatePaneTo(pane, data.path);
                        }
                    }
                }
            });
        });

        // ==================== FILE OPERATIONS ====================

        this.socket.on('directory_created', (data) => {
            // Only show notification if NOT in batch upload mode
            // During batch uploads, we create many folders and don't want spam
            if (!this.currentUploadBatch) {
                this.showNotification(`${this.t('fm.folderCreated', 'Folder created')}: ${data.path}`, 'success');
            }
            this.refreshBothPanes();
        });

        this.socket.on('file_renamed', (data) => {
            this.showNotification(this.t('fm.renamedSuccess', 'Renamed successfully'), 'success');
            this.refreshBothPanes();
        });

        this.socket.on('item_deleted', (data) => {
            this.showNotification(`${this.t('fm.deleted', 'Deleted')}: ${data.path}`, 'success');
            this.refreshBothPanes();
        });

        // ==================== TRANSFERS ====================

        this.socket.on('file_progress', (data) => {
            this.updateTransferProgress(data);
        });

        this.socket.on('file_complete', (data) => {
            this.completeTransfer(data, 'upload');

            // Update batch upload progress
            if (this.currentUploadBatch && data.type === 'upload') {
                this.currentUploadBatch.completed++;
                this.showUploadProgress();

                // Check if batch is complete
                if (this.currentUploadBatch.completed >= this.currentUploadBatch.total) {
                    this.showUploadComplete();
                    // Clear batch tracking
                    window._currentUploadBatchId = null;
                    this.currentUploadBatch = null;
                }
            }
        });

        this.socket.on('file_download_ready_binary', (data) => {
            this.handleDownloadReady(data);
        });

        // ==================== SERVER-TO-SERVER TRANSFER ====================

        this.socket.on('s2s_transfer_started', (data) => {
            this.showNotification(this.t('fm.transferStarted', 'Server-to-server transfer started'), 'info');
        });

        this.socket.on('s2s_transfer_progress', (data) => {
            this.updateTransferProgress(data);
        });

        this.socket.on('s2s_transfer_complete', (data) => {
            this.showNotification(`${this.t('fm.transferComplete', 'Transfer complete')}: ${data.filename}`, 'success');
            this.refreshBothPanes();
            this.completeS2STransfer(data);
        });

        this.socket.on('s2s_transfer_error', (data) => {
            this.showNotification(`${this.t('fm.transferFailed', 'Transfer failed')}: ${data.error}`, 'error');
            this.failS2STransfer(data);
        });

        // ==================== QUICK CONNECT ====================

        this.socket.on('quick_connect_success', (data) => {
            this.handleQuickConnectSuccess(data);
        });

        this.socket.on('quick_connect_error', (data) => {
            this.showNotification(`${this.t('fm.qc.connectionFailed', 'Connection failed')}: ${data.error}`, 'error');
            // Reset Quick Connect button
            const btn = document.getElementById('fmQcConnectBtn');
            if (btn) {
                btn.disabled = false;
                btn.querySelector('.btn-label').textContent = this.t('fm.qc.connect', 'Connect');
                btn.querySelector('.btn-spinner')?.classList.add('hidden');
            }
        });

        // ==================== ERROR HANDLING ====================

        this.socket.on('error', (data) => {
            const errorMsg = data.error || data.message || 'Unknown error';
            console.error('[FM] SFTP Error received:', errorMsg, data);

            // Always clear loading state for any SSH pane that's currently loading.
            // Any server error during an SFTP operation should stop the loading spinner
            // and show the error, regardless of the error message content.
            ['left', 'right'].forEach(pane => {
                const state = this.panes[pane];
                if (state.loading && state.type === 'ssh') {
                    if (state.loadingTimeout) {
                        clearTimeout(state.loadingTimeout);
                        state.loadingTimeout = null;
                    }
                    state.loading = false;
                    state.error = errorMsg;
                    this.renderPane(pane);
                }
            });

            this.showNotification(errorMsg, 'error');
        });

        // ==================== FILE EXISTS CHECK ====================

        this.socket.on('file_exists_result', (data) => {
            if (this.pendingConflictCheck) {
                this.pendingConflictCheck(data);
                this.pendingConflictCheck = null;
            }
        });
    }

    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            if (!this.isOpen) return;

            // Escape
            if (e.key === 'Escape') {
                this.closeContextMenu();
                if (!this.hasOpenDialogs()) {
                    this.close();
                }
            }

            // Tab to switch panes
            if (e.key === 'Tab' && !e.target.matches('input, select')) {
                e.preventDefault();
                this.setActivePane(this.activePane === 'left' ? 'right' : 'left');
            }

            // Ctrl+A to select all
            if (e.ctrlKey && e.key === 'a' && !e.target.matches('input')) {
                e.preventDefault();
                this.selectAll();
            }

            // Delete
            if (e.key === 'Delete' && !e.target.matches('input')) {
                e.preventDefault();
                this.deleteSelected();
            }

            // F5 to transfer
            if (e.key === 'F5') {
                e.preventDefault();
                this.executeTransfer();
            }

            // F7 for new folder
            if (e.key === 'F7') {
                e.preventDefault();
                this.createNewFolder();
            }

            // F2 to rename
            if (e.key === 'F2') {
                e.preventDefault();
                this.renameSelected();
            }

            // Enter to open
            if (e.key === 'Enter' && !e.target.matches('input')) {
                e.preventDefault();
                const state = this.panes[this.activePane];
                if (state.selected.size === 1) {
                    const index = Array.from(state.selected)[0];
                    this.handleItemDblClick(this.activePane, index);
                }
            }
        });
    }

    // ==================== MODAL CONTROL ====================

    open() {
        this.isOpen = true;
        this.modal.classList.add('show');
        this.applyTranslations();
        this.updateSessionLists();

        // Get current terminal session
        const currentSession = typeof SessionManager !== 'undefined' ? SessionManager.getActiveSession() : null;

        // CRITICAL: Apply mobile mode via JS class (bypasses CSS cache issues)
        const isMobileNow = this.isMobile();
        console.log('[FM] Opening file manager, isMobile:', isMobileNow, 'innerWidth:', window.innerWidth);

        if (isMobileNow) {
            // Mobile: Single pane mode - add class and force right pane
            this.modal.classList.add('fm-mobile-mode');
            document.getElementById('fmLeftPane').style.display = 'none';
            document.getElementById('fmRightPane').style.display = 'flex';
            document.getElementById('fmRightPane').classList.add('active');
            document.getElementById('fmLeftPane').classList.remove('active');
            this.activePane = 'right';

            // Auto-connect to current session
            if (currentSession) {
                document.getElementById('fmRightSource').value = `ssh:${currentSession}`;
                this.onSourceChange('right', `ssh:${currentSession}`);
            }
        } else {
            // Desktop/Tablet: Normal dual-pane mode
            this.modal.classList.remove('fm-mobile-mode');
            document.getElementById('fmLeftPane').style.display = '';
            document.getElementById('fmRightPane').style.display = '';
            this.setActivePane('left');
            this.updateMobilePaneTabs('left');

            // Auto-select current terminal session for right pane
            if (currentSession) {
                document.getElementById('fmRightSource').value = `ssh:${currentSession}`;
                this.onSourceChange('right', `ssh:${currentSession}`);
            }
        }
    }

    close() {
        this.isOpen = false;
        this.modal.classList.remove('show');
        this.closeContextMenu();

        // Clean up drag-drop state
        if (window.dragDropManager) {
            window.dragDropManager.reset();
        }

        // Remove drop-target classes from panes
        ['left', 'right'].forEach(pane => {
            const paneEl = document.getElementById(`fm${this.capitalize(pane)}Pane`);
            if (paneEl) {
                paneEl.classList.remove('drop-target');
            }
        });

        // Clean up upload progress notification if visible
        if (this.uploadProgressNotification) {
            this.uploadProgressNotification.remove();
            this.uploadProgressNotification = null;
        }
    }

    hasOpenDialogs() {
        return document.querySelector('.fm-conflict-dialog') !== null ||
               this.qcModal.classList.contains('show');
    }

    // ==================== SOURCE SELECTION ====================

    updateSessionLists() {
        const sessions = typeof SessionManager !== 'undefined' ? SessionManager.getAllSessions() : [];
        this.availableSessions = sessions.filter(s => s.connected);

        ['Left', 'Right'].forEach(side => {
            const group = document.getElementById(`fm${side}Sessions`);
            group.innerHTML = '';

            this.availableSessions.forEach(session => {
                const option = document.createElement('option');
                option.value = `ssh:${session.id}`;
                option.textContent = `${session.username}@${session.host}`;
                group.appendChild(option);
            });

            // Add quick connections
            this.quickConnections.forEach(qc => {
                const option = document.createElement('option');
                option.value = `qc:${qc.connectionId}`;
                option.textContent = `${qc.username}@${qc.host} (quick)`;
                group.appendChild(option);
            });
        });
    }

    async onSourceChange(pane, value) {
        const state = this.panes[pane];

        // Clear any existing loading timeout
        if (state.loadingTimeout) {
            clearTimeout(state.loadingTimeout);
            state.loadingTimeout = null;
        }

        // Reset state
        state.files = [];
        state.selected.clear();
        state.loading = true;
        state.error = null;
        this.renderPane(pane);

        if (!value) {
            state.type = null;
            state.sessionId = null;
            state.connectionId = null;
            state.loading = false;
            this.renderPane(pane);
            this.updatePaneBadge(pane);
            return;
        }

        if (value === 'browser-local') {
            // File System Access API
            if (!this.browserFS.isSupported) {
                this.showNotification(this.t('fm.fsaNotSupported', 'File System Access API not supported. Use drag & drop instead.'), 'warning');
                state.loading = false;
                this.renderPane(pane);
                return;
            }

            const granted = await this.browserFS.requestAccess();
            if (granted) {
                state.type = 'browser-local';
                state.sessionId = null;
                state.connectionId = null;
                state.path = this.browserFS.getCurrentPath();
                state.hostInfo = { host: this.t('fm.yourComputer', 'Your Computer'), username: '', port: '' };
                await this.refreshBrowserPane(pane);
            } else {
                state.loading = false;
                this.renderPane(pane);
            }
            this.updatePaneBadge(pane);

        } else if (value === 'quick-connect') {
            // Show quick connect dialog
            this.pendingQuickConnectPane = pane;
            this.openQuickConnect();
            // Reset dropdown to previous value
            const select = document.getElementById(`fm${this.capitalize(pane)}Source`);
            select.value = state.type === 'ssh' ? `ssh:${state.sessionId || state.connectionId}` : '';
            state.loading = false;

        } else if (value.startsWith('ssh:')) {
            // Existing terminal session
            const sessionId = value.substring(4);
            state.type = 'ssh';
            state.sessionId = sessionId;
            state.connectionId = null;

            const session = this.availableSessions.find(s => s.id === sessionId);
            if (session) {
                state.hostInfo = { host: session.host, username: session.username, port: session.port };
            }

            // Get home directory and list
            this.socket.emit('get_home_directory', { session_id: sessionId });
            this.socket.emit('list_directory', { session_id: sessionId, remote_path: '/' });
            this.updatePaneBadge(pane);

            // Set loading timeout (10 seconds)
            this.setLoadingTimeout(pane);

        } else if (value.startsWith('qc:')) {
            // Quick connection
            const connectionId = value.substring(3);
            const qc = this.quickConnections.find(c => c.connectionId === connectionId);

            state.type = 'ssh';
            state.sessionId = null;
            state.connectionId = connectionId;

            if (qc) {
                state.hostInfo = { host: qc.host, username: qc.username, port: qc.port };
            }

            this.socket.emit('get_home_directory', { session_id: connectionId });
            this.socket.emit('list_directory', { session_id: connectionId, remote_path: '/' });
            this.updatePaneBadge(pane);

            // Set loading timeout (10 seconds)
            this.setLoadingTimeout(pane);
        }
    }

    /**
     * Set a timeout for loading state - shows error if loading takes too long
     */
    setLoadingTimeout(pane, timeout = 10000) {
        const state = this.panes[pane];

        // Clear existing timeout
        if (state.loadingTimeout) {
            clearTimeout(state.loadingTimeout);
        }

        state.loadingTimeout = setTimeout(() => {
            if (state.loading) {
                state.loading = false;
                state.error = this.t('fm.connectionTimeout', 'Connection timeout - could not load directory');
                this.renderPane(pane);
                this.showNotification(this.t('fm.loadTimeout', 'Failed to load directory: timeout'), 'error');
            }
        }, timeout);
    }

    updatePaneBadge(pane) {
        const state = this.panes[pane];
        const badge = document.getElementById(`fm${this.capitalize(pane)}Badge`);

        if (!state.type) {
            badge.textContent = '';
            badge.className = 'fm-host-badge';
            return;
        }

        if (state.type === 'browser-local') {
            badge.textContent = this.t('fm.yourComputer', 'Your Computer');
            badge.className = 'fm-host-badge browser';
        } else if (state.hostInfo) {
            badge.textContent = `${state.hostInfo.username}@${state.hostInfo.host}`;
            badge.className = 'fm-host-badge ssh';
        }
    }

    // ==================== QUICK CONNECT ====================

    openQuickConnect() {
        // Load available profiles
        if (this.socket) {
            this.socket.emit('list_profiles');
            this.socket.once('profiles_list', (data) => {
                const select = document.getElementById('fmQcProfile');
                select.innerHTML = '<option value="">-- Enter manually --</option>';
                this.qcProfiles = data.profiles || [];
                this.qcProfiles.forEach(profile => {
                    const option = document.createElement('option');
                    option.value = profile.id;
                    option.textContent = `${profile.name} (${profile.username}@${profile.host})`;
                    select.appendChild(option);
                });
            });

            // Load available SSH keys
            this.socket.emit('list_keys');
            this.socket.once('keys_list', (data) => {
                const select = document.getElementById('fmQcKeySelect');
                select.innerHTML = '<option value="">-- Select Key --</option>';
                this.qcKeys = data.keys || [];
                this.qcKeys.forEach(key => {
                    const option = document.createElement('option');
                    option.value = key.id;
                    option.textContent = `${key.name} (${key.type || 'unknown'})`;
                    select.appendChild(option);
                });
            });
        }

        this.qcModal.classList.add('show');
        document.getElementById('fmQcHost').focus();
    }

    /**
     * Handle profile selection in Quick Connect dialog
     */
    onProfileSelect(profileId) {
        if (!profileId) {
            // Reset form when "Enter manually" is selected
            document.getElementById('fmQcHost').value = '';
            document.getElementById('fmQcPort').value = '22';
            document.getElementById('fmQcUsername').value = '';
            document.getElementById('fmQcPassword').value = '';
            return;
        }

        const profile = (this.qcProfiles || []).find(p => p.id == profileId);
        if (!profile) return;

        // Fill form with profile data
        document.getElementById('fmQcHost').value = profile.host || '';
        document.getElementById('fmQcPort').value = profile.port || 22;
        document.getElementById('fmQcUsername').value = profile.username || '';

        // Set auth type
        const authType = profile.key_id ? 'key' : 'password';
        document.querySelector(`input[name="fmQcAuth"][value="${authType}"]`).checked = true;
        document.getElementById('fmQcPasswordGroup').classList.toggle('hidden', authType !== 'password');
        document.getElementById('fmQcKeyGroup').classList.toggle('hidden', authType !== 'key');

        if (profile.key_id) {
            document.getElementById('fmQcKeySelect').value = profile.key_id;
        }

        // Focus password field if password auth
        if (authType === 'password') {
            document.getElementById('fmQcPassword').focus();
        }
    }

    closeQuickConnect() {
        this.qcModal.classList.remove('show');
        this.pendingQuickConnectPane = null;
        document.getElementById('fmQcForm').reset();
        // Reset profile selector
        document.getElementById('fmQcProfile').value = '';
        // Reset auth type visibility
        document.getElementById('fmQcPasswordGroup').classList.remove('hidden');
        document.getElementById('fmQcKeyGroup').classList.add('hidden');
    }

    submitQuickConnect() {
        const host = document.getElementById('fmQcHost').value.trim();
        const port = parseInt(document.getElementById('fmQcPort').value) || 22;
        const username = document.getElementById('fmQcUsername').value.trim();
        const authType = document.querySelector('input[name="fmQcAuth"]:checked').value;
        const password = document.getElementById('fmQcPassword').value;
        const keyId = document.getElementById('fmQcKeySelect').value;

        if (!host || !username) {
            this.showNotification(this.t('fm.qc.hostRequired', 'Host and username are required'), 'warning');
            return;
        }

        if (authType === 'password' && !password) {
            this.showNotification(this.t('fm.qc.passwordRequired', 'Password is required'), 'warning');
            return;
        }

        if (authType === 'key' && !keyId) {
            this.showNotification(this.t('fm.qc.selectSshKey', 'Please select an SSH key'), 'warning');
            return;
        }

        const data = { host, port, username };
        if (authType === 'password') {
            data.password = password;
        } else {
            data.key_id = keyId;
        }

        this.socket.emit('quick_connect', data);
        this.showNotification(this.t('fm.connecting', 'Connecting...'), 'info');
    }

    handleQuickConnectSuccess(data) {
        this.showNotification(`${this.t('fm.connected', 'Connected')}: ${data.host}`, 'success');

        // Store quick connection
        const qc = {
            connectionId: data.connection_id,
            host: data.host,
            port: data.port,
            username: data.username
        };
        this.quickConnections.push(qc);

        // Update session lists
        this.updateSessionLists();

        // Set the pane to this connection
        if (this.pendingQuickConnectPane) {
            const pane = this.pendingQuickConnectPane;
            const state = this.panes[pane];

            state.type = 'ssh';
            state.sessionId = null;
            state.connectionId = data.connection_id;
            state.hostInfo = { host: data.host, username: data.username, port: data.port };

            // Update dropdown
            const select = document.getElementById(`fm${this.capitalize(pane)}Source`);
            select.value = `qc:${data.connection_id}`;

            // Request directory listing
            state.loading = true;
            this.renderPane(pane);
            this.socket.emit('get_home_directory', { session_id: data.connection_id });
            this.socket.emit('list_directory', { session_id: data.connection_id, remote_path: '/' });
            this.setLoadingTimeout(pane);

            this.updatePaneBadge(pane);
        }

        this.closeQuickConnect();
    }

    // ==================== NAVIGATION ====================

    async navigatePaneTo(pane, path) {
        const state = this.panes[pane];

        if (!state.type) {
            this.showNotification(this.t('fm.selectSourceFirst', 'Please select a source first'), 'warning');
            return;
        }

        state.selected.clear();
        state.loading = true;
        this.renderPane(pane);

        if (state.type === 'browser-local') {
            try {
                await this.browserFS.navigateTo(path);
                state.path = this.browserFS.getCurrentPath();
                state.files = await this.browserFS.listDirectory();
                state.loading = false;
                this.updatePathInput(pane, state.path);
                this.renderPane(pane);
            } catch (e) {
                this.showNotification(`${this.t('fm.cannotNavigate', 'Cannot navigate to')} ${path}`, 'error');
                state.loading = false;
                this.renderPane(pane);
            }
        } else if (state.type === 'ssh') {
            const sessionId = state.sessionId || state.connectionId;
            this.socket.emit('list_directory', { session_id: sessionId, remote_path: path });
            this.setLoadingTimeout(pane);
        }
    }

    async navigatePaneUp(pane) {
        const state = this.panes[pane];

        if (!state.type) return;

        if (state.type === 'browser-local') {
            const navigated = await this.browserFS.navigateUp();
            if (navigated) {
                await this.refreshBrowserPane(pane);
            }
        } else if (state.type === 'ssh') {
            if (state.path === '/') return;
            const parentPath = state.path.split('/').slice(0, -1).join('/') || '/';
            this.navigatePaneTo(pane, parentPath);
        }
    }

    navigatePaneHome(pane) {
        const state = this.panes[pane];

        if (!state.type) return;

        if (state.type === 'browser-local') {
            this.browserFS.currentHandle = this.browserFS.rootHandle;
            this.browserFS.pathStack = [this.browserFS.rootHandle.name];
            this.refreshBrowserPane(pane);
        } else if (state.type === 'ssh') {
            const homePath = state.homePath || '/';
            this.navigatePaneTo(pane, homePath);
        }
    }

    async navigateIntoDir(pane, dirName) {
        const state = this.panes[pane];

        if (state.type === 'browser-local') {
            try {
                await this.browserFS.navigateInto(dirName);
                await this.refreshBrowserPane(pane);
            } catch (e) {
                this.showNotification(`${this.t('fm.cannotOpen', 'Cannot open')} ${dirName}`, 'error');
            }
        } else if (state.type === 'ssh') {
            const newPath = state.path === '/' ? '/' + dirName : state.path + '/' + dirName;
            this.navigatePaneTo(pane, newPath);
        }
    }

    async refreshPane(pane) {
        const state = this.panes[pane];

        if (!state.type) return;

        state.loading = true;
        this.renderPane(pane);

        if (state.type === 'browser-local') {
            await this.refreshBrowserPane(pane);
        } else if (state.type === 'ssh') {
            const sessionId = state.sessionId || state.connectionId;
            this.socket.emit('list_directory', { session_id: sessionId, remote_path: state.path });
            this.setLoadingTimeout(pane);
        }
    }

    async refreshBrowserPane(pane) {
        const state = this.panes[pane];
        try {
            state.files = await this.browserFS.listDirectory();
            state.path = this.browserFS.getCurrentPath();
            state.loading = false;
            this.updatePathInput(pane, state.path);
            this.renderPane(pane);
        } catch (e) {
            this.showNotification(this.t('fm.errorReadingDir', 'Error reading directory'), 'error');
            state.loading = false;
            this.renderPane(pane);
        }
    }

    refreshBothPanes() {
        this.refreshPane('left');
        this.refreshPane('right');
    }

    updatePathInput(pane, path) {
        document.getElementById(`fm${this.capitalize(pane)}Path`).value = path;
    }

    // ==================== RENDERING ====================

    renderPane(pane) {
        const state = this.panes[pane];
        const container = document.getElementById(`fm${this.capitalize(pane)}List`);

        // Loading state
        if (state.loading) {
            container.innerHTML = `
                <div class="fm-loading">
                    <div class="fm-loading-spinner"></div>
                    ${this.t('fm.loading', 'Loading...')}
                </div>
            `;
            this.updatePaneStatus(pane);
            return;
        }

        // Error state
        if (state.error) {
            container.innerHTML = `
                <div class="fm-error">
                    <span class="material-icons fm-error-icon">error_outline</span>
                    <div class="fm-error-text">${this.escapeHtml(state.error)}</div>
                    <button class="btn btn-secondary btn-sm fm-error-retry" data-pane="${pane}">
                        <span class="material-icons">refresh</span>
                        ${this.t('fm.retry', 'Retry')}
                    </button>
                </div>
            `;
            // Add retry handler
            container.querySelector('.fm-error-retry')?.addEventListener('click', () => {
                state.error = null;
                this.refreshPane(pane);
            });
            this.updatePaneStatus(pane);
            return;
        }

        // No source selected
        if (!state.type) {
            container.innerHTML = `
                <div class="fm-empty">
                    <span class="material-icons fm-empty-icon">folder_open</span>
                    <div class="fm-empty-text">${this.t('fm.selectSourceAbove', 'Select a source above')}</div>
                </div>
            `;
            this.updatePaneStatus(pane);
            return;
        }

        // Empty directory
        if (state.files.length === 0) {
            container.innerHTML = `
                <div class="fm-empty">
                    <span class="material-icons fm-empty-icon">folder_off</span>
                    <div class="fm-empty-text">${this.t('fm.emptyDirectory', 'Empty directory')}</div>
                </div>
            `;
            this.updatePaneStatus(pane);
            return;
        }

        // Sort files: directories first, then alphabetically
        const sortedFiles = [...state.files].sort((a, b) => {
            if (a.is_dir && !b.is_dir) return -1;
            if (!a.is_dir && b.is_dir) return 1;
            return a.name.localeCompare(b.name);
        });

        // Create index mapping
        const indexMap = new Map();
        sortedFiles.forEach((file, sortedIndex) => {
            const originalIndex = state.files.indexOf(file);
            indexMap.set(sortedIndex, originalIndex);
        });

        // Build HTML
        let html = '';

        // Parent directory
        if (state.path !== '/' && !(state.type === 'browser-local' && this.browserFS.pathStack.length <= 1)) {
            html += `
                <div class="fm-file-item directory" data-index="-1" data-type="parent">
                    <span class="material-icons fm-file-icon parent">arrow_upward</span>
                    <div class="fm-file-info">
                        <div class="fm-file-name">..</div>
                        <div class="fm-file-meta">${this.t('fm.parentDirectory', 'Parent directory')}</div>
                    </div>
                    <div class="fm-file-size">-</div>
                </div>
            `;
        }

        html += sortedFiles.map((file, sortedIndex) => {
            const originalIndex = indexMap.get(sortedIndex);
            const icon = file.is_dir ? 'folder' : this.getFileIcon(file.name);
            return `
                <div class="fm-file-item ${file.is_dir ? 'directory' : ''} ${state.selected.has(originalIndex) ? 'selected' : ''}"
                     data-index="${originalIndex}"
                     data-type="${file.is_dir ? 'directory' : 'file'}"
                     data-name="${this.escapeHtml(file.name)}"
                     draggable="true">
                    <span class="material-icons fm-file-icon ${file.is_dir ? 'folder' : 'file'}">${icon}</span>
                    <div class="fm-file-info">
                        <div class="fm-file-name">${this.escapeHtml(file.name)}</div>
                        <div class="fm-file-meta">${file.permissions || ''}</div>
                    </div>
                    <div class="fm-file-size">${file.is_dir ? '-' : this.formatSize(file.size || 0)}</div>
                </div>
            `;
        }).join('');

        container.innerHTML = html;

        // Event listeners
        container.querySelectorAll('.fm-file-item').forEach(item => {
            const index = parseInt(item.dataset.index);
            item.addEventListener('click', (e) => this.handleItemClick(e, pane, index));
            item.addEventListener('dblclick', (e) => {
                e.preventDefault();
                e.stopPropagation();
                this.handleItemDblClick(pane, index);
            });
            item.addEventListener('contextmenu', (e) => this.showContextMenu(e, pane, index));
            item.addEventListener('dragstart', (e) => this.handleDragStart(e, pane, index));
        });

        this.updatePaneStatus(pane);
    }

    // ==================== SELECTION ====================

    handleItemClick(e, pane, index) {
        e.stopPropagation();
        this.setActivePane(pane);

        if (index === -1) return; // Parent directory

        const state = this.panes[pane];

        if (e.ctrlKey || e.metaKey) {
            if (state.selected.has(index)) {
                state.selected.delete(index);
            } else {
                state.selected.add(index);
            }
        } else if (e.shiftKey && state.lastSelected !== -1) {
            const start = Math.min(state.lastSelected, index);
            const end = Math.max(state.lastSelected, index);
            for (let i = start; i <= end; i++) {
                state.selected.add(i);
            }
        } else {
            state.selected.clear();
            state.selected.add(index);
        }

        state.lastSelected = index;
        this.updateSelectionVisual(pane);
    }

    handleItemDblClick(pane, index) {
        const state = this.panes[pane];
        console.log('[SFTP] handleItemDblClick called:', { pane, index, type: state.type, sessionId: state.sessionId, connectionId: state.connectionId });

        if (index === -1) {
            this.navigatePaneUp(pane);
            return;
        }

        const file = state.files[index];
        if (!file) {
            console.log('[SFTP] No file at index:', index);
            return;
        }

        console.log('[SFTP] File info:', { name: file.name, is_dir: file.is_dir });

        if (file.is_dir) {
            this.navigateIntoDir(pane, file.name);
        } else {
            // File - open preview for any SSH connection type
            if (state.type === 'ssh') {
                const sessionId = state.sessionId || state.connectionId;
                const filePath = this.joinPath(state.path, file.name);
                console.log('[SFTP] Opening preview:', { sessionId, filePath, hasFilePreview: !!window.FilePreview });
                if (window.FilePreview) {
                    window.FilePreview.open(sessionId, filePath, file.name);
                } else {
                    console.error('[SFTP] FilePreview not available');
                }
            } else if (state.type === 'browser-local') {
                // For local files, could potentially open with File System Access API
                // For now, show a notification
                this.showNotification('Local file preview not yet supported', 'info');
            } else {
                console.log('[SFTP] Unknown state type for preview:', state.type);
            }
        }
    }

    updateSelectionVisual(pane) {
        const state = this.panes[pane];
        const container = document.getElementById(`fm${this.capitalize(pane)}List`);

        container.querySelectorAll('.fm-file-item').forEach(item => {
            const idx = parseInt(item.dataset.index);
            if (idx >= 0) {
                item.classList.toggle('selected', state.selected.has(idx));
            }
        });

        this.updatePaneStatus(pane);
    }

    setActivePane(pane) {
        // Mobile: Always force right pane (server) - no pane switching allowed
        if (this.isMobile()) {
            pane = 'right';
        }

        this.activePane = pane;
        document.getElementById('fmLeftPane').classList.toggle('active', pane === 'left');
        document.getElementById('fmRightPane').classList.toggle('active', pane === 'right');
        this.updateMobilePaneTabs(pane);
    }

    // ==================== MOBILE UI ====================

    isMobile() {
        return window.innerWidth < 768;
    }

    updateMobilePaneTabs(pane) {
        document.querySelectorAll('.fm-pane-tab').forEach(tab => {
            tab.classList.toggle('active', tab.dataset.pane === pane);
        });
    }

    setupLongPress() {
        let longPressTimer = null;
        const longPressDuration = 500;

        ['left', 'right'].forEach(pane => {
            const listEl = document.getElementById(`fm${this.capitalize(pane)}List`);

            listEl.addEventListener('touchstart', (e) => {
                const item = e.target.closest('.fm-file-item');
                if (!item) return;

                longPressTimer = setTimeout(() => {
                    e.preventDefault();
                    const index = parseInt(item.dataset.index);
                    this.setActivePane(pane);
                    this.panes[pane].selected.clear();
                    this.panes[pane].selected.add(index);
                    this.updateSelectionVisual(pane);
                    this.showActionSheet();
                }, longPressDuration);
            }, { passive: false });

            listEl.addEventListener('touchend', () => {
                if (longPressTimer) {
                    clearTimeout(longPressTimer);
                    longPressTimer = null;
                }
            });

            listEl.addEventListener('touchmove', () => {
                if (longPressTimer) {
                    clearTimeout(longPressTimer);
                    longPressTimer = null;
                }
            });
        });
    }

    showActionSheet() {
        const sheet = document.getElementById('fmActionSheet');
        if (sheet) {
            sheet.classList.add('visible');
        }
    }

    hideActionSheet() {
        const sheet = document.getElementById('fmActionSheet');
        if (sheet) {
            sheet.classList.remove('visible');
        }
    }

    handleActionSheetAction(action) {
        this.hideActionSheet();

        switch (action) {
            case 'open':
                const state = this.panes[this.activePane];
                if (state.selected.size === 1) {
                    const index = Array.from(state.selected)[0];
                    const file = state.files[index];
                    if (file && file.is_dir) {
                        this.navigateToFile(this.activePane, file);
                    }
                }
                break;
            case 'download':
                this.downloadSelected();
                break;
            case 'transfer':
                this.executeTransfer();
                break;
            case 'rename':
                this.renameSelected();
                break;
            case 'newfolder':
                this.createNewFolder();
                break;
            case 'delete':
                this.deleteSelected();
                break;
            case 'cancel':
                // Just close the sheet
                break;
        }
    }

    handleMobileUpload(e) {
        const files = e.target.files;
        if (!files || files.length === 0) return;

        const state = this.panes[this.activePane];
        console.log('[FM] Mobile upload - activePane:', this.activePane, 'state:', {
            type: state.type,
            sessionId: state.sessionId,
            connectionId: state.connectionId,
            path: state.path
        });

        if (!state.type) {
            this.showNotification(this.t('fm.selectConnectionFirst', 'Please select a connection first'), 'warning');
            return;
        }

        if (state.type === 'ssh') {
            const sessionId = state.sessionId || state.connectionId;
            if (!sessionId) {
                this.showNotification(this.t('fm.noActiveConnection', 'No active connection'), 'error');
                return;
            }

            console.log('[FM] Starting upload of', files.length, 'files to', state.path, 'via session', sessionId);
            this.showNotification(`${this.t('fm.uploading', 'Uploading')} ${files.length} ${this.t('fm.files', 'file(s)')}...`, 'info');

            Array.from(files).forEach(file => {
                this.uploadFileToBrowser(file, state.path, sessionId);
            });
        } else {
            this.showNotification(this.t('fm.uploadSSHOnly', 'Upload only available for SSH connections'), 'warning');
        }

        // Clear the input for next upload
        e.target.value = '';
    }

    uploadFileToBrowser(file, remotePath, sessionId) {
        const self = this;

        // Build full remote path (directory + filename)
        const fullRemotePath = remotePath.endsWith('/')
            ? remotePath + file.name
            : remotePath + '/' + file.name;

        console.log('[FM] Starting HTTP upload:', file.name, 'size:', file.size, 'to:', fullRemotePath);

        // Add to transfer queue
        const transferId = `upload-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        self.queueTransfer({
            id: transferId,
            type: 'upload',
            filename: file.name,
            size: file.size,
            source: 'local',
            destination: remotePath
        });

        // Use HTTP POST for reliable file upload (bypasses Socket.IO binary issues)
        const formData = new FormData();
        formData.append('file', file);
        formData.append('session_id', sessionId);
        formData.append('remote_path', fullRemotePath);

        // Include CSRF token for security
        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content
            || document.querySelector('input[name="csrf_token"]')?.value;
        const headers = {};
        if (csrfToken) {
            headers['X-CSRFToken'] = csrfToken;
        }

        fetch('/api/upload', {
            method: 'POST',
            body: formData,
            headers: headers,
            credentials: 'same-origin'
        })
        .then(response => response.json().then(data => ({ status: response.status, data })))
        .then(({ status, data }) => {
            if (status === 200 && data.success) {
                self.completeTransferById(transferId);
                self.refreshPane(self.activePane);
                self.showNotification(`${file.name} ${self.t('fm.uploaded', 'uploaded')}`, 'success');
            } else {
                self.failTransferById(transferId, data.error || 'Upload failed');
                self.showNotification(`${self.t('fm.uploadError', 'Upload error')}: ${data.error || self.t('fm.unknown', 'Unknown')}`, 'error');
            }
        })
        .catch(err => {
            console.error('[FM] Upload error:', err);
            self.failTransferById(transferId, err.message);
            self.showNotification(`${self.t('fm.uploadError', 'Upload error')}: ${err.message}`, 'error');
        });
    }

    selectAll() {
        const state = this.panes[this.activePane];
        state.files.forEach((_, index) => state.selected.add(index));
        this.updateSelectionVisual(this.activePane);
    }

    // ==================== FILE OPERATIONS ====================

    createNewFolder() {
        const state = this.panes[this.activePane];

        if (!state.type) {
            this.showNotification(this.t('fm.selectSourceFirst', 'Please select a source first'), 'warning');
            return;
        }

        const name = prompt(this.t('fm.enterFolderName', 'Enter folder name:'));
        if (!name) return;

        if (name.includes('/') || name.includes('\\')) {
            this.showNotification(this.t('fm.invalidFolderName', 'Invalid folder name'), 'error');
            return;
        }

        if (state.type === 'browser-local') {
            this.browserFS.createDirectory(name)
                .then(() => {
                    this.showNotification(`${this.t('fm.folderCreated', 'Folder created')}: ${name}`, 'success');
                    this.refreshBrowserPane(this.activePane);
                })
                .catch(e => this.showNotification(`${this.t('common.error', 'Error')}: ${e.message}`, 'error'));
        } else if (state.type === 'ssh') {
            const path = state.path === '/' ? '/' + name : state.path + '/' + name;
            const sessionId = state.sessionId || state.connectionId;
            this.socket.emit('create_directory', { session_id: sessionId, remote_path: path });
        }
    }

    deleteSelected() {
        const state = this.panes[this.activePane];

        if (state.selected.size === 0) {
            this.showNotification(this.t('fm.noItemsSelected', 'No items selected'), 'warning');
            return;
        }

        const items = Array.from(state.selected).map(i => state.files[i]).filter(f => f);
        const names = items.map(f => f.name).join(', ');

        if (!confirm(`${this.t('fm.confirmDelete', 'Delete')} ${items.length} ${this.t('fm.items', 'item(s)')}?\n\n${names}\n\n${this.t('fm.cannotBeUndone', 'This cannot be undone!')}`)) {
            return;
        }

        if (state.type === 'browser-local') {
            Promise.all(items.map(item => this.browserFS.deleteEntry(item.name)))
                .then(() => {
                    this.showNotification(this.t('fm.itemsDeleted', 'Items deleted'), 'success');
                    state.selected.clear();
                    this.refreshBrowserPane(this.activePane);
                })
                .catch(e => this.showNotification(`${this.t('common.error', 'Error')}: ${e.message}`, 'error'));
        } else if (state.type === 'ssh') {
            const sessionId = state.sessionId || state.connectionId;
            items.forEach(item => {
                const path = state.path === '/' ? '/' + item.name : state.path + '/' + item.name;
                this.socket.emit('delete_item', { session_id: sessionId, path: path });
            });
            state.selected.clear();
        }
    }

    renameSelected() {
        const state = this.panes[this.activePane];

        if (state.selected.size !== 1) {
            this.showNotification(this.t('fm.selectOneToRename', 'Select exactly one item to rename'), 'warning');
            return;
        }

        const index = Array.from(state.selected)[0];
        const file = state.files[index];
        if (!file) return;

        const newName = prompt(this.t('fm.enterNewName', 'Enter new name:'), file.name);
        if (!newName || newName === file.name) return;

        if (newName.includes('/') || newName.includes('\\')) {
            this.showNotification(this.t('fm.invalidName', 'Invalid name'), 'error');
            return;
        }

        if (state.type === 'browser-local') {
            this.browserFS.rename(file.name, newName)
                .then(() => {
                    this.showNotification(this.t('fm.renamedSuccess', 'Renamed successfully'), 'success');
                    this.refreshBrowserPane(this.activePane);
                })
                .catch(e => this.showNotification(`${this.t('common.error', 'Error')}: ${e.message}`, 'error'));
        } else if (state.type === 'ssh') {
            const sessionId = state.sessionId || state.connectionId;
            const oldPath = state.path === '/' ? '/' + file.name : state.path + '/' + file.name;
            const newPath = state.path === '/' ? '/' + newName : state.path + '/' + newName;
            this.socket.emit('rename_file', { session_id: sessionId, old_path: oldPath, new_path: newPath });
        }
    }

    // ==================== TRANSFERS ====================

    async executeTransfer() {
        const sourcePane = this.activePane;
        const targetPane = sourcePane === 'left' ? 'right' : 'left';

        const source = this.panes[sourcePane];
        const target = this.panes[targetPane];

        if (!source.type || !target.type) {
            this.showNotification(this.t('fm.bothPanesRequired', 'Both panes must have a source selected'), 'warning');
            return;
        }

        if (source.selected.size === 0) {
            this.showNotification(this.t('fm.noItemsForTransfer', 'No items selected for transfer'), 'warning');
            return;
        }

        const selectedItems = Array.from(source.selected)
            .map(i => source.files[i])
            .filter(f => f);

        if (selectedItems.length === 0) {
            this.showNotification(this.t('fm.noValidItems', 'No valid items selected'), 'warning');
            return;
        }

        // Determine transfer type
        const transferType = `${source.type}-to-${target.type}`;
        this.showNotification(`${this.t('fm.startingTransfer', 'Starting transfer of')} ${selectedItems.length} ${this.t('fm.items', 'item(s)')}...`, 'info');

        for (const item of selectedItems) {
            const sourcePath = source.path === '/' ? '/' + item.name : source.path + '/' + item.name;
            const targetPath = target.path === '/' ? '/' + item.name : target.path + '/' + item.name;

            switch (transferType) {
                case 'browser-local-to-ssh':
                    await this.transferBrowserToSSH(item, targetPath, target);
                    break;

                case 'ssh-to-browser-local':
                    await this.transferSSHToBrowser(sourcePath, source, item.name);
                    break;

                case 'ssh-to-ssh':
                    await this.transferSSHtoSSH(sourcePath, source, targetPath, target, item);
                    break;

                default:
                    this.showNotification(`${this.t('fm.transferNotSupported', 'Transfer type not supported')}: ${transferType}`, 'error');
            }
        }
    }

    async transferBrowserToSSH(item, targetPath, targetPane) {
        const sessionId = targetPane.sessionId || targetPane.connectionId;

        if (item.is_dir) {
            // Recursive folder upload
            await this.uploadBrowserFolderToSSH(item.handle, targetPath, sessionId);
        } else {
            // Single file upload
            try {
                const data = await this.browserFS.readFile(item.handle);
                this.socket.emit('upload_file_binary', {
                    session_id: sessionId,
                    filename: item.name,
                    file_data: data,
                    remote_path: targetPath
                });
                this.queueTransfer({
                    type: 'upload',
                    filename: item.name,
                    targetPath: targetPath,
                    size: data.byteLength
                });
            } catch (e) {
                this.showNotification(`${this.t('fm.failedToRead', 'Failed to read')} ${item.name}: ${e.message}`, 'error');
            }
        }
    }

    async uploadBrowserFolderToSSH(dirHandle, remotePath, sessionId) {
        // Create remote directory
        this.socket.emit('create_directory', { session_id: sessionId, remote_path: remotePath });
        await new Promise(r => setTimeout(r, 100));

        // Iterate entries
        for await (const entry of dirHandle.values()) {
            const entryPath = remotePath + '/' + entry.name;

            if (entry.kind === 'directory') {
                await this.uploadBrowserFolderToSSH(entry, entryPath, sessionId);
            } else {
                try {
                    const file = await entry.getFile();
                    const data = await file.arrayBuffer();
                    this.socket.emit('upload_file_binary', {
                        session_id: sessionId,
                        filename: entry.name,
                        file_data: data,
                        remote_path: entryPath
                    });
                    this.queueTransfer({
                        type: 'upload',
                        filename: entry.name,
                        targetPath: entryPath,
                        size: data.byteLength
                    });
                } catch (e) {
                    console.error('Failed to upload:', entry.name, e);
                }
            }
        }
    }

    async transferSSHToBrowser(sourcePath, sourcePane, filename) {
        const sessionId = sourcePane.sessionId || sourcePane.connectionId;

        // Queue the download and wait for response
        this.pendingBrowserDownload = {
            filename: filename,
            callback: async (data) => {
                try {
                    await this.browserFS.writeFile(filename, data);
                    this.showNotification(`${this.t('fm.saved', 'Saved')}: ${filename}`, 'success');
                    await this.refreshBrowserPane(this.activePane === 'left' ? 'right' : 'left');
                } catch (e) {
                    this.showNotification(`${this.t('fm.failedToSave', 'Failed to save')} ${filename}: ${e.message}`, 'error');
                }
            }
        };

        this.socket.emit('download_file_binary', {
            session_id: sessionId,
            remote_path: sourcePath
        });

        this.queueTransfer({
            type: 'download',
            filename: filename,
            sourcePath: sourcePath
        });
    }

    async transferSSHtoSSH(sourcePath, sourcePane, targetPath, targetPane, item) {
        const sourceSessionId = sourcePane.sessionId || sourcePane.connectionId;
        const targetSessionId = targetPane.sessionId || targetPane.connectionId;

        // Same host - just copy/rename
        if (sourceSessionId === targetSessionId) {
            this.showNotification(this.t('fm.cannotTransferSameHost', 'Cannot transfer to same host. Use rename instead.'), 'warning');
            return;
        }

        // Server-to-server transfer
        const transferId = `s2s_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        this.socket.emit('transfer_server_to_server', {
            source_session_id: sourceSessionId,
            source_path: sourcePath,
            dest_session_id: targetSessionId,
            dest_path: targetPath,
            transfer_id: transferId,
            is_dir: item.is_dir
        });

        this.queueTransfer({
            id: transferId,
            type: 's2s',
            filename: item.name,
            sourcePath: sourcePath,
            targetPath: targetPath,
            size: item.size || 0
        });
    }

    // ==================== DRAG & DROP ====================

    handleDrop(e, targetPane) {
        const files = e.dataTransfer.files;
        const items = e.dataTransfer.items;
        const target = this.panes[targetPane];

        // Dropping from other pane (internal transfer)
        if (this.dragSource && this.dragSource !== targetPane && this.draggedItems.length > 0) {
            // Set active pane to source, then transfer
            this.activePane = this.dragSource;
            this.executeTransfer();
            this.draggedItems = [];
            this.dragSource = null;
            return;
        }

        // Dropping from desktop
        if (target.type === 'ssh') {
            // Verify session exists
            const sessionId = target.sessionId || target.connectionId;
            if (!sessionId) {
                this.showNotification(this.t('fm.noActiveSession', 'No active SSH session'), 'error');
                return;
            }

            // Try to use DataTransferItems API for folder support
            if (items && items.length > 0) {
                const entries = Array.from(items)
                    .filter(item => item.kind === 'file')
                    .map(item => item.webkitGetAsEntry())
                    .filter(entry => entry !== null);

                if (entries.length > 0) {
                    this.uploadDesktopItemsToSSH(entries, target);
                } else if (files && files.length > 0) {
                    // Fallback to files if no entries
                    this.uploadDesktopFilesToSSH(Array.from(files), target);
                }
            } else if (files && files.length > 0) {
                // Fallback for browsers without DataTransferItems support
                this.uploadDesktopFilesToSSH(Array.from(files), target);
            }
        } else if (target.type === 'browser-local') {
            this.showNotification(this.t('fm.useFilesystemForLocal', 'Use your file system to add files to your local folder'), 'info');
        } else {
            // No source selected
            this.showNotification(this.t('fm.selectSourceFirst', 'Please select a source first'), 'warning');
        }

        this.draggedItems = [];
        this.dragSource = null;
    }

    /**
     * Upload files (DataTransfer API entries) to SSH - supports folders
     */
    async uploadDesktopItemsToSSH(entries, targetPane) {
        const sessionId = targetPane.sessionId || targetPane.connectionId;
        const basePath = targetPane.path;

        // Count total files first
        const countFiles = async (entry) => {
            if (entry.isFile) {
                return 1;
            } else if (entry.isDirectory) {
                const reader = entry.createReader();
                const subEntries = await new Promise((resolve, reject) => {
                    reader.readEntries(resolve, reject);
                });
                let count = 0;
                for (const subEntry of subEntries) {
                    count += await countFiles(subEntry);
                }
                return count;
            }
            return 0;
        };

        let totalFiles = 0;
        for (const entry of entries) {
            totalFiles += await countFiles(entry);
        }

        // Initialize upload progress tracking with unique batch ID
        const batchId = `batch_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        this.currentUploadBatch = {
            id: batchId,
            total: totalFiles,
            completed: 0,
            sessionId: sessionId
        };

        // Store batch ID globally to suppress individual notifications
        window._currentUploadBatchId = batchId;

        // Show initial notification
        this.showUploadProgress();

        // Process entries
        for (const entry of entries) {
            if (entry.isFile) {
                entry.file(file => {
                    this.uploadSingleFileToSSH(file, basePath, sessionId, true);
                });
            } else if (entry.isDirectory) {
                await this.uploadDirectoryToSSH(entry, basePath, sessionId, true);
            }
        }

        // Refresh pane after ALL uploads complete (debounced)
        if (this.uploadRefreshTimer) {
            clearTimeout(this.uploadRefreshTimer);
        }
        this.uploadRefreshTimer = setTimeout(() => {
            this.refreshPane(this.getPaneForSession(sessionId));
            this.uploadRefreshTimer = null;
        }, 2000);
    }

    /**
     * Upload a single file to SSH
     */
    uploadSingleFileToSSH(file, basePath, sessionId, isBatchUpload = false) {
        const remotePath = this.joinPath(basePath, file.name);

        const reader = new FileReader();
        reader.onload = () => {
            this.socket.emit('upload_file_binary', {
                session_id: sessionId,
                filename: file.name,
                file_data: reader.result,
                remote_path: remotePath
            });

            if (!isBatchUpload) {
                // Only queue individual transfers if not part of batch
                this.queueTransfer({
                    type: 'upload',
                    filename: file.name,
                    targetPath: remotePath,
                    size: file.size
                });
            }
        };
        reader.readAsArrayBuffer(file);
    }

    /**
     * Upload directory recursively to SSH
     */
    async uploadDirectoryToSSH(directoryEntry, basePath, sessionId, isBatchUpload = false) {
        const dirPath = this.joinPath(basePath, directoryEntry.name);

        // Create directory on remote (non-blocking)
        this.socket.emit('create_directory', {
            session_id: sessionId,
            remote_path: dirPath
        });

        // Read directory contents
        const reader = directoryEntry.createReader();
        const entries = await new Promise((resolve, reject) => {
            reader.readEntries(resolve, reject);
        });

        // Process all entries recursively (in parallel for speed)
        const promises = [];
        for (const entry of entries) {
            if (entry.isFile) {
                entry.file(file => {
                    this.uploadSingleFileToSSH(file, dirPath, sessionId, isBatchUpload);
                });
            } else if (entry.isDirectory) {
                promises.push(this.uploadDirectoryToSSH(entry, dirPath, sessionId, isBatchUpload));
            }
        }

        // Wait for all subdirectories to complete
        await Promise.all(promises);
    }

    /**
     * Upload files (legacy File API) to SSH - files only, no folders
     */
    async uploadDesktopFilesToSSH(files, targetPane) {
        const sessionId = targetPane.sessionId || targetPane.connectionId;

        for (const file of files) {
            this.uploadSingleFileToSSH(file, targetPane.path, sessionId);
        }

        // Refresh pane after ALL uploads complete (debounced)
        if (this.uploadRefreshTimer) {
            clearTimeout(this.uploadRefreshTimer);
        }
        this.uploadRefreshTimer = setTimeout(() => {
            this.refreshPane(this.getPaneForSession(sessionId));
            this.uploadRefreshTimer = null;
        }, 2000);
    }

    /**
     * Get pane ('left' or 'right') for a session ID
     */
    getPaneForSession(sessionId) {
        if (this.panes.left.sessionId === sessionId || this.panes.left.connectionId === sessionId) {
            return 'left';
        }
        if (this.panes.right.sessionId === sessionId || this.panes.right.connectionId === sessionId) {
            return 'right';
        }
        return 'left'; // Default
    }

    handleDragStart(e, pane, index) {
        this.dragSource = pane;
        const state = this.panes[pane];

        if (!state.selected.has(index)) {
            state.selected.clear();
            state.selected.add(index);
            this.updateSelectionVisual(pane);
        }

        this.draggedItems = Array.from(state.selected).map(i => state.files[i]).filter(f => f);
        e.dataTransfer.effectAllowed = 'copy';
        e.dataTransfer.setData('text/plain', this.draggedItems.map(f => f.name).join(', '));
    }

    // ==================== TRANSFER QUEUE ====================

    queueTransfer(transfer) {
        if (!transfer.id) {
            transfer.id = Date.now() + Math.random();
        }
        transfer.status = 'pending';
        transfer.progress = 0;
        this.transferQueue.push(transfer);
        this.renderTransferQueue();
        this.processTransferQueue();
    }

    async processTransferQueue() {
        if (this.isTransferring) return;

        const pending = this.transferQueue.find(t => t.status === 'pending');
        if (!pending) return;

        this.isTransferring = true;
        pending.status = 'active';
        this.renderTransferQueue();

        // S2S transfers are handled by backend
        if (pending.type === 's2s') {
            // Just wait - backend will send progress/complete events
            this.activeTransfers.set(pending.id, pending);
            return;
        }

        // Other transfers complete via socket events
        this.activeTransfers.set(pending.id, pending);
    }

    updateTransferProgress(data) {
        const transfer = this.transferQueue.find(t =>
            t.status === 'active' &&
            (t.filename === data.filename || t.id === data.transfer_id)
        );

        if (transfer) {
            transfer.progress = data.percent || 0;
            this.renderTransferQueue();
        }
    }

    completeTransfer(data, type) {
        const transfer = this.transferQueue.find(t =>
            t.status === 'active' && t.type === type
        );

        if (transfer) {
            transfer.status = 'complete';
            transfer.progress = 100;
            this.activeTransfers.delete(transfer.id);
            this.isTransferring = false;
            this.renderTransferQueue();
            this.refreshBothPanes();
            setTimeout(() => this.processTransferQueue(), 100);
        }
    }

    completeS2STransfer(data) {
        const transfer = this.transferQueue.find(t => t.id === data.transfer_id);
        if (transfer) {
            transfer.status = 'complete';
            transfer.progress = 100;
            this.activeTransfers.delete(transfer.id);
            this.isTransferring = false;
            this.renderTransferQueue();
            setTimeout(() => this.processTransferQueue(), 100);
        }
    }

    failS2STransfer(data) {
        const transfer = this.transferQueue.find(t => t.id === data.transfer_id);
        if (transfer) {
            transfer.status = 'error';
            transfer.error = data.error;
            this.activeTransfers.delete(transfer.id);
            this.isTransferring = false;
            this.renderTransferQueue();
            setTimeout(() => this.processTransferQueue(), 100);
        }
    }

    completeTransferById(transferId) {
        const transfer = this.transferQueue.find(t => t.id === transferId);
        if (transfer) {
            transfer.status = 'complete';
            transfer.progress = 100;
            this.activeTransfers.delete(transfer.id);
            this.isTransferring = false;
            this.renderTransferQueue();
            setTimeout(() => this.processTransferQueue(), 100);
        }
    }

    failTransferById(transferId, error) {
        const transfer = this.transferQueue.find(t => t.id === transferId);
        if (transfer) {
            transfer.status = 'error';
            transfer.error = error;
            this.activeTransfers.delete(transfer.id);
            this.isTransferring = false;
            this.renderTransferQueue();
            setTimeout(() => this.processTransferQueue(), 100);
        }
    }

    /**
     * Download all selected items to the browser
     */
    downloadSelected() {
        const state = this.panes[this.activePane];

        if (state.selected.size === 0) {
            this.showNotification(this.t('fm.noItemsSelected', 'No items selected'), 'warning');
            return;
        }

        if (state.type !== 'ssh') {
            this.showNotification(this.t('fm.downloadOnlySSH', 'Download only works for SSH sources'), 'warning');
            return;
        }

        const sessionId = state.sessionId || state.connectionId;
        const items = Array.from(state.selected).map(i => state.files[i]).filter(f => f);

        this.showNotification(`${this.t('fm.downloading', 'Downloading')} ${items.length} ${this.t('fm.items', 'item(s)')}...`, 'info');

        for (const item of items) {
            const filePath = this.joinPath(state.path, item.name);
            if (item.is_dir) {
                this.downloadFolderToBrowser(sessionId, filePath, item.name);
            } else {
                this.downloadFileToBrowser(sessionId, filePath, item.name);
            }
        }
    }

    /**
     * Download a file directly to the browser (context menu action)
     */
    downloadFileToBrowser(sessionId, remotePath, filename) {
        this.showNotification(`${this.t('fm.downloading', 'Downloading')}: ${filename}...`, 'info');

        // Queue the transfer for UI feedback
        this.queueTransfer({
            type: 'download',
            filename: filename,
            sourcePath: remotePath,
            size: 0
        });

        // Request the download (without for_preview flag - will trigger browser download)
        this.socket.emit('download_file_binary', {
            session_id: sessionId,
            remote_path: remotePath
            // No for_preview flag = handleDownloadReady will trigger browser save
        });
    }

    /**
     * Download a folder as ZIP directly to the browser (context menu action)
     */
    downloadFolderToBrowser(sessionId, remotePath, folderName) {
        this.showNotification(`${this.t('fm.downloadingFolder', 'Downloading folder')}: ${folderName}...`, 'info');

        // Queue the transfer for UI feedback
        this.queueTransfer({
            type: 'download',
            filename: `${folderName}.zip`,
            sourcePath: remotePath,
            size: 0
        });

        // Request the folder download (will be zipped on server)
        this.socket.emit('download_folder_binary', {
            session_id: sessionId,
            remote_path: remotePath
        });
    }

    async handleDownloadReady(data) {
        // Ignore downloads that are for preview (handled by FilePreview)
        if (data.for_preview) {
            return;
        }

        // Check for pending browser download (for transfer to other pane)
        if (this.pendingBrowserDownload && this.pendingBrowserDownload.filename === data.filename) {
            await this.pendingBrowserDownload.callback(data.file_data);
            this.pendingBrowserDownload = null;
            this.completeTransfer(data, 'download');
            return;
        }

        // Browser download - save file to user's computer
        const blob = new Blob([data.file_data]);
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = data.filename;
        a.click();
        URL.revokeObjectURL(url);

        this.showNotification(`${this.t('fm.downloaded', 'Downloaded')}: ${data.filename}`, 'success');
        this.completeTransfer(data, 'download');
    }

    renderTransferQueue() {
        const container = document.getElementById('fmQueueList');
        const badge = document.getElementById('fmQueueBadge');

        const activeCount = this.transferQueue.filter(t =>
            t.status === 'pending' || t.status === 'active'
        ).length;

        badge.textContent = activeCount;
        badge.style.display = activeCount > 0 ? 'inline' : 'none';

        if (this.transferQueue.length === 0) {
            container.innerHTML = `<div class="fm-empty" style="padding: 20px;">${this.t('fm.noTransfers', 'No transfers')}</div>`;
            return;
        }

        container.innerHTML = this.transferQueue.slice(-20).map(t => `
            <div class="fm-transfer-item ${t.status}">
                <div class="fm-transfer-icon ${t.type}">
                    ${t.type === 'upload' ? '⬆️' : t.type === 'download' ? '⬇️' : '↔️'}
                </div>
                <div class="fm-transfer-info">
                    <div class="fm-transfer-name">${this.escapeHtml(t.filename)}</div>
                    ${t.status === 'active' ? `
                        <div class="fm-transfer-progress-bar">
                            <div class="fm-transfer-progress-fill" style="width: ${t.progress}%"></div>
                        </div>
                    ` : ''}
                </div>
                <div class="fm-transfer-status ${t.status}">${this.getStatusText(t)}</div>
            </div>
        `).join('');
    }

    getStatusText(transfer) {
        switch (transfer.status) {
            case 'pending': return this.t('fm.waiting', 'Waiting...');
            case 'active': return `${transfer.progress}%`;
            case 'complete': return `✓ ${this.t('fm.done', 'Done')}`;
            case 'error': return `✗ ${this.t('fm.failed', 'Failed')}`;
            default: return '';
        }
    }

    toggleQueue() {
        document.getElementById('fmQueue').classList.toggle('collapsed');
        const toggle = document.getElementById('fmQueueToggle');
        toggle.textContent = toggle.textContent === '▼' ? '▲' : '▼';
    }

    // ==================== CONTEXT MENU ====================

    showContextMenu(e, pane, index) {
        e.preventDefault();
        e.stopPropagation();
        this.closeContextMenu();

        const state = this.panes[pane];
        const file = index >= 0 ? state.files[index] : null;

        const menu = document.createElement('div');
        menu.className = 'fm-context-menu';

        let items = [];

        if (file) {
            if (file.is_dir) {
                items.push({ action: 'open', icon: '📂', text: this.t('fm.ctx.open', 'Open') });
                // Download folder as ZIP for SSH panes
                if (state.type === 'ssh' || state.type === 'quick-connect') {
                    items.push({ action: 'download', icon: '⬇️', text: this.t('fm.ctx.download', 'Download') });
                }
            } else {
                // File - show preview and download options for SSH panes
                if (state.type === 'ssh' || state.type === 'quick-connect') {
                    items.push({ action: 'preview', icon: '👁️', text: this.t('fm.ctx.preview', 'Preview') });
                    items.push({ action: 'download', icon: '⬇️', text: this.t('fm.ctx.download', 'Download') });
                }
            }
            // Only show transfer option on desktop/tablet (not mobile - single pane mode)
            if (!this.isMobile()) {
                items.push({ action: 'transfer', icon: '↔️', text: this.t('fm.ctx.transferToOther', 'Transfer to other pane') });
            }
            items.push({ divider: true });
            items.push({ action: 'rename', icon: '✏️', text: this.t('fm.rename', 'Rename') });
        }

        items.push({ action: 'newfolder', icon: '📁', text: this.t('fm.newFolder', 'New Folder') });
        items.push({ action: 'refresh', icon: '↻', text: this.t('fm.refresh', 'Refresh') });

        if (file) {
            items.push({ divider: true });
            items.push({ action: 'delete', icon: '🗑️', text: this.t('fm.delete', 'Delete'), danger: true });
        }

        menu.innerHTML = items.map(item => {
            if (item.divider) {
                return '<div class="fm-context-divider"></div>';
            }
            return `
                <div class="fm-context-item ${item.danger ? 'danger' : ''}" data-action="${item.action}">
                    <span class="fm-context-icon">${item.icon}</span> ${item.text}
                </div>
            `;
        }).join('');

        document.body.appendChild(menu);
        this.contextMenu = menu;

        menu.style.left = `${Math.min(e.clientX, window.innerWidth - 200)}px`;
        menu.style.top = `${Math.min(e.clientY, window.innerHeight - 200)}px`;

        menu.querySelectorAll('.fm-context-item').forEach(item => {
            item.addEventListener('click', (ev) => {
                ev.stopPropagation();
                this.handleContextAction(item.dataset.action, pane, index);
                this.closeContextMenu();
            });
        });
    }

    handleContextAction(action, pane, index) {
        const state = this.panes[pane];
        this.activePane = pane;

        // Helper: If clicked item is already selected, use all selected items
        // Otherwise, operate only on the clicked item
        const ensureSelection = () => {
            if (index >= 0 && !state.selected.has(index)) {
                state.selected.clear();
                state.selected.add(index);
                this.updateSelectionVisual(pane);
            }
        };

        switch (action) {
            case 'open':
                this.handleItemDblClick(pane, index);
                break;
            case 'preview':
                if (index >= 0) {
                    const file = state.files[index];
                    if (file && !file.is_dir) {
                        const sessionId = state.sessionId || state.connectionId;
                        const filePath = this.joinPath(state.path, file.name);
                        if (window.FilePreview) {
                            window.FilePreview.open(sessionId, filePath, file.name);
                        }
                    }
                }
                break;
            case 'download':
                ensureSelection();
                this.downloadSelected();
                break;
            case 'transfer':
                ensureSelection();
                this.executeTransfer();
                break;
            case 'rename':
                // Rename only works on single item
                if (index >= 0) {
                    state.selected.clear();
                    state.selected.add(index);
                    this.renameSelected();
                }
                break;
            case 'newfolder':
                this.createNewFolder();
                break;
            case 'refresh':
                this.refreshPane(pane);
                break;
            case 'delete':
                ensureSelection();
                this.deleteSelected();
                break;
        }
    }

    closeContextMenu() {
        if (this.contextMenu) {
            this.contextMenu.remove();
            this.contextMenu = null;
        }
    }

    // ==================== STATUS ====================

    updatePaneStatus(pane) {
        const state = this.panes[pane];
        const count = state.files.length;
        const selected = state.selected.size;
        const totalSize = Array.from(state.selected)
            .reduce((sum, i) => sum + (state.files[i]?.size || 0), 0);

        document.getElementById(`fm${this.capitalize(pane)}Count`).textContent =
            `${count} ${this.t('fm.items', 'items')}`;

        document.getElementById(`fm${this.capitalize(pane)}Selected`).textContent = selected > 0
            ? `${selected} ${this.t('fm.selected', 'selected')} (${this.formatSize(totalSize)})`
            : '';
    }

    // ==================== UTILITIES ====================

    /**
     * Get translated string with i18n support
     * @param {string} key - Translation key
     * @param {string} fallback - Fallback text if translation not found
     * @returns {string} Translated string
     */
    t(key, fallback = '') {
        if (window.i18n && typeof window.i18n.t === 'function') {
            return window.i18n.t(key) || fallback;
        }
        return fallback;
    }

    /**
     * Apply translations to all elements with data-i18n attributes
     */
    applyTranslations() {
        if (!window.i18n || typeof window.i18n.t !== 'function') return;

        // Translate text content
        this.modal.querySelectorAll('[data-i18n]').forEach(el => {
            const key = el.getAttribute('data-i18n');
            const translation = window.i18n.t(key);
            if (translation) el.textContent = translation;
        });

        // Translate title attributes
        this.modal.querySelectorAll('[data-i18n-title]').forEach(el => {
            const key = el.getAttribute('data-i18n-title');
            const translation = window.i18n.t(key);
            if (translation) el.title = translation;
        });

        // Translate optgroup labels
        this.modal.querySelectorAll('[data-i18n-label]').forEach(el => {
            const key = el.getAttribute('data-i18n-label');
            const translation = window.i18n.t(key);
            if (translation) el.label = translation;
        });

        // Also apply to Quick Connect modal
        if (this.qcModal) {
            this.qcModal.querySelectorAll('[data-i18n]').forEach(el => {
                const key = el.getAttribute('data-i18n');
                const translation = window.i18n.t(key);
                if (translation) el.textContent = translation;
            });

            this.qcModal.querySelectorAll('[data-i18n-title]').forEach(el => {
                const key = el.getAttribute('data-i18n-title');
                const translation = window.i18n.t(key);
                if (translation) el.title = translation;
            });
        }
    }

    capitalize(str) {
        return str.charAt(0).toUpperCase() + str.slice(1);
    }

    formatSize(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    /**
     * Join path components for remote paths
     * @param {string} basePath - Base directory path
     * @param {string} filename - File or directory name to append
     * @returns {string} Combined path
     */
    joinPath(basePath, filename) {
        if (!basePath || basePath === '/') {
            return '/' + filename;
        }
        // Remove trailing slash if present
        const cleanBase = basePath.endsWith('/') ? basePath.slice(0, -1) : basePath;
        return cleanBase + '/' + filename;
    }

    /**
     * Get Material Icon name for a file based on its extension
     */
    getFileIcon(filename) {
        const ext = filename.split('.').pop()?.toLowerCase();
        const iconMap = {
            // Documents
            'pdf': 'picture_as_pdf',
            'doc': 'description', 'docx': 'description',
            'xls': 'table_chart', 'xlsx': 'table_chart', 'csv': 'table_chart',
            'ppt': 'slideshow', 'pptx': 'slideshow',
            'txt': 'article', 'md': 'article', 'rtf': 'article',
            // Code
            'js': 'javascript', 'ts': 'javascript', 'jsx': 'javascript', 'tsx': 'javascript',
            'py': 'code', 'rb': 'code', 'go': 'code', 'rs': 'code', 'c': 'code', 'cpp': 'code', 'h': 'code',
            'java': 'code', 'php': 'code', 'swift': 'code', 'kt': 'code',
            'html': 'html', 'htm': 'html',
            'css': 'css', 'scss': 'css', 'sass': 'css', 'less': 'css',
            'json': 'data_object', 'xml': 'data_object', 'yaml': 'data_object', 'yml': 'data_object',
            'sql': 'storage',
            'sh': 'terminal', 'bash': 'terminal', 'zsh': 'terminal',
            // Images
            'jpg': 'image', 'jpeg': 'image', 'png': 'image', 'gif': 'image',
            'svg': 'image', 'webp': 'image', 'ico': 'image', 'bmp': 'image',
            // Media
            'mp3': 'audio_file', 'wav': 'audio_file', 'ogg': 'audio_file', 'flac': 'audio_file',
            'mp4': 'video_file', 'mkv': 'video_file', 'avi': 'video_file', 'mov': 'video_file', 'webm': 'video_file',
            // Archives
            'zip': 'folder_zip', 'tar': 'folder_zip', 'gz': 'folder_zip', 'rar': 'folder_zip', '7z': 'folder_zip',
            // Config
            'env': 'settings', 'ini': 'settings', 'conf': 'settings', 'config': 'settings',
            'lock': 'lock',
            // Misc
            'log': 'receipt_long',
            'key': 'key', 'pem': 'key', 'pub': 'key',
        };
        return iconMap[ext] || 'insert_drive_file';
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    showUploadProgress() {
        if (!this.currentUploadBatch) return;

        const { completed, total } = this.currentUploadBatch;
        const percent = Math.round((completed / total) * 100);

        // Create or update progress notification
        if (!this.uploadProgressNotification) {
            // Create notification element
            this.uploadProgressNotification = document.createElement('div');
            this.uploadProgressNotification.className = 'upload-progress-notification';
            this.uploadProgressNotification.innerHTML = `
                <div class="upload-progress-content">
                    <div class="upload-progress-icon">
                        <span class="material-icons spinning">cloud_upload</span>
                    </div>
                    <div class="upload-progress-info">
                        <div class="upload-progress-text">${this.t('fm.uploadingFiles', 'Uploading files')}...</div>
                        <div class="upload-progress-stats">
                            <span class="upload-progress-count">${completed} / ${total}</span>
                            <span class="upload-progress-percent">${percent}%</span>
                        </div>
                        <div class="upload-progress-bar">
                            <div class="upload-progress-fill" style="width: ${percent}%"></div>
                        </div>
                    </div>
                </div>
            `;

            // Add styles
            if (!document.getElementById('upload-progress-styles')) {
                const style = document.createElement('style');
                style.id = 'upload-progress-styles';
                style.textContent = `
                    .upload-progress-notification {
                        position: fixed;
                        top: 80px;
                        right: 20px;
                        background: var(--bg-secondary);
                        border: 1px solid var(--border-color);
                        border-radius: 8px;
                        padding: 16px;
                        min-width: 300px;
                        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
                        z-index: 10000;
                        animation: slideInRight 0.3s ease;
                    }
                    .upload-progress-notification.success {
                        background: var(--success-bg, #1e4d2b);
                        border-color: var(--success-color, #4ade80);
                    }
                    .upload-progress-content {
                        display: flex;
                        gap: 12px;
                        align-items: flex-start;
                    }
                    .upload-progress-icon {
                        font-size: 32px;
                        color: var(--accent-primary);
                    }
                    .upload-progress-icon.success {
                        color: var(--success-color, #4ade80);
                    }
                    .upload-progress-icon .spinning {
                        animation: spin 1s linear infinite;
                    }
                    .upload-progress-info {
                        flex: 1;
                    }
                    .upload-progress-text {
                        font-weight: 500;
                        margin-bottom: 8px;
                    }
                    .upload-progress-stats {
                        display: flex;
                        justify-content: space-between;
                        font-size: 12px;
                        color: var(--text-secondary);
                        margin-bottom: 8px;
                    }
                    .upload-progress-bar {
                        height: 6px;
                        background: var(--bg-primary);
                        border-radius: 3px;
                        overflow: hidden;
                    }
                    .upload-progress-fill {
                        height: 100%;
                        background: var(--accent-primary);
                        transition: width 0.3s ease;
                    }
                    @keyframes slideInRight {
                        from {
                            transform: translateX(400px);
                            opacity: 0;
                        }
                        to {
                            transform: translateX(0);
                            opacity: 1;
                        }
                    }
                    @keyframes spin {
                        to { transform: rotate(360deg); }
                    }
                    @keyframes slideOutRight {
                        from {
                            transform: translateX(0);
                            opacity: 1;
                        }
                        to {
                            transform: translateX(400px);
                            opacity: 0;
                        }
                    }
                `;
                document.head.appendChild(style);
            }

            document.body.appendChild(this.uploadProgressNotification);
        } else {
            // Update existing notification
            const countEl = this.uploadProgressNotification.querySelector('.upload-progress-count');
            const percentEl = this.uploadProgressNotification.querySelector('.upload-progress-percent');
            const fillEl = this.uploadProgressNotification.querySelector('.upload-progress-fill');

            if (countEl) countEl.textContent = `${completed} / ${total}`;
            if (percentEl) percentEl.textContent = `${percent}%`;
            if (fillEl) fillEl.style.width = `${percent}%`;
        }
    }

    showUploadComplete() {
        if (!this.uploadProgressNotification) return;

        // Update to success state
        this.uploadProgressNotification.classList.add('success');
        this.uploadProgressNotification.innerHTML = `
            <div class="upload-progress-content">
                <div class="upload-progress-icon success">
                    <span class="material-icons">check_circle</span>
                </div>
                <div class="upload-progress-info">
                    <div class="upload-progress-text">${this.t('fm.uploadComplete', 'Upload complete')}!</div>
                    <div class="upload-progress-stats">
                        <span>${this.currentUploadBatch ? this.currentUploadBatch.total : 0} ${this.t('fm.filesUploaded', 'files uploaded')}</span>
                    </div>
                </div>
            </div>
        `;

        // Remove after 3 seconds
        setTimeout(() => {
            if (this.uploadProgressNotification) {
                this.uploadProgressNotification.style.animation = 'slideOutRight 0.3s ease';
                setTimeout(() => {
                    if (this.uploadProgressNotification) {
                        this.uploadProgressNotification.remove();
                        this.uploadProgressNotification = null;
                    }
                }, 300);
            }
        }, 3000);
    }

    showNotification(message, type = 'info') {
        if (window.showNotification) {
            window.showNotification(message, type);
        } else {
            console.log(`[${type}] ${message}`);
        }
    }
}

// ==================== GLOBAL INIT ====================

let sftpFileManager = null;

function openFileManager() {
    if (!sftpFileManager) {
        sftpFileManager = new SFTPFileManager();
    }
    sftpFileManager.open();
}

window.SFTPFileManager = SFTPFileManager;
window.openFileManager = openFileManager;
