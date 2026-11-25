(function() {
    'use strict';

    const FilePreview = {
        modal: null,
        currentSourceId: null,
        currentPath: null,
        currentFilename: null,
        currentPreviewRequestId: null,
        currentEditRequestId: null,
        currentSaveRequestId: null,
        requestSequence: 0,
        saveRequests: new Map(),
        lastSavedSequence: 0,
        editMode: false,
        _previewPanel: 'previewLoading',
        _previewTruncated: false,
        _previewEditable: false,
        saveOutcomeUnknown: false,
        dirty: false,
        editEncoding: 'utf-8',
        editNewline: 'lf',
        editRevision: null,
        editBaseline: null,
        editOriginalBytes: null,
        editTarget: null,
        editReview: null,
        recoverableReplaceSources: new Set(),
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
            document.getElementById('editorCommitBtn')?.addEventListener('click', () => this.commitReviewedEdit());
            document.getElementById('editorBackBtn')?.addEventListener('click', () => this.dismissEditReview());
            document.getElementById('editorBackupBtn')?.addEventListener('click', () => this.downloadOriginal());
            document.getElementById('editorDraftBtn')?.addEventListener('click', () => this.downloadDraft());
            document.getElementById('editorReloadBtn')?.addEventListener('click', () => this.open(this.currentSourceId, this.currentPath, this.currentFilename));
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
            if (!bytes) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
        },

        normalizeSourceId(sourceId) {
            if (typeof sourceId !== 'string' || !sourceId.trim()) return null;
            const normalized = sourceId.trim();
            return normalized.includes(':')
                ? normalized
                : `sftp-session:${normalized}`;
        },

        nextRequestId(operation) {
            this.requestSequence += 1;
            return `file-preview:${operation}:${Date.now().toString(36)}:${this.requestSequence}`;
        },

        matchesResponse(data, requestId) {
            return Boolean(
                data
                && data.source_id === this.currentSourceId
                && data.request_id === requestId
            );
        },

        open(sourceId, path, filename) {
            if (this.editMode && (this.dirty || this.pendingSaveContent != null) && !window.confirm(window.i18n
                ? i18n.t('editor.unsavedConfirm') : 'Discard unsaved changes?')) return;
            this.setSaveOutcomeUnknown(false);
            this.resetEditReview();
            this.editBaseline = null;
            this.editOriginalBytes = null;
            this.editTarget = null;
            this.currentSourceId = this.normalizeSourceId(sourceId);
            if (!this.currentSourceId) return;
            this.currentPath = path;
            this.currentFilename = filename;
            this.clearPendingSave();
            this.saveRequests.clear();
            this.currentPreviewRequestId = this.nextRequestId('open');
            this.currentEditRequestId = null;
            this.currentSaveRequestId = null;

            // Start every open in a clean (non-edit) state.
            this._previewFullContent = null;
            this.pendingSaveContent = null;
            this.editMode = false;
            this.dirty = false;
            this.detachBeforeUnload();
            document.getElementById('fileEditor')?.classList.add('hidden');
            this.modal?.classList.remove('editing');
            this.hideEditButton();
            this.showPreviewActions();

            const fileType = this.getFileType(filename);

            this.showLoading();
            window.ModalManager.open(this.modal);

            document.getElementById('previewFilename').textContent = filename;
            document.getElementById('previewSize').textContent = '';

            if (fileType === 'image') {
                this.loadImage(
                    this.currentSourceId,
                    path,
                    filename,
                    this.currentPreviewRequestId
                );
            } else {
                const options = {
                    source_id: this.currentSourceId,
                    path: path,
                    request_id: this.currentPreviewRequestId,
                };

                if (fileType === 'log') {
                    options.tail_lines = 1000;
                }

                socket.emit('preview_file', options);
            }
        },

        loadImage(sourceId, path, filename, requestId) {
            if (this._pendingImageHandler) {
                socket.off('file_download_ready_binary', this._pendingImageHandler);
                this._pendingImageHandler = null;
            }

            const requestPath = path;
            socket.emit('download_file_binary', {
                source_id: sourceId,
                remote_path: path,
                for_preview: true,
                request_id: requestId,
            });

            const handleBinaryDownload = (data) => {
                if (!data.for_preview) return;
                if (this.currentPath !== requestPath
                        || !this.matchesResponse(data, requestId)) return;

                socket.off('file_download_ready_binary', handleBinaryDownload);
                this._pendingImageHandler = null;

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
            if (!this.matchesResponse(data, this.currentPreviewRequestId)) return;
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
            if (!this.matchesResponse(data, this.currentPreviewRequestId)) return;
            this.hideLoading();
            this.showError(data.error);
        },

        handleSocketError(data) {
            if (data?.operation === 'download_file_binary'
                    && this.matchesResponse(data, this.currentPreviewRequestId)) {
                this.handlePreviewError(data);
                return true;
            }
            if (data?.operation === 'save_file'
                    && this.matchesResponse(data, this.currentSaveRequestId)) {
                if (data.code === 'SAVE_OUTCOME_UNKNOWN') {
                    this.interruptSave();
                    return true;
                }
                this.clearPendingSave();
                const status = document.getElementById('editorStatus');
                if (data.code === 'SMB_RECOVERABLE_REPLACE_REQUIRED') {
                    if (this.recoverableReplaceSources.has(this.currentSourceId)) {
                        this.saveReviewedEdit('recoverable_swap', data.save_challenge);
                        return true;
                    }
                    const prompt = window.i18n
                        ? i18n.t('editor.recoverableConfirm')
                        : 'This server cannot replace the file in one safe step. WebSSH can save it with a temporary recovery backup and restore the original if replacement fails. Use this method for this SMB connection until the page is reloaded?';
                    if (window.confirm(prompt)) {
                        this.recoverableReplaceSources.add(this.currentSourceId);
                        this.saveReviewedEdit('recoverable_swap', data.save_challenge);
                    } else if (status) {
                        status.textContent = window.i18n
                            ? i18n.t('editor.recoverableDeclined')
                            : 'Save cancelled. Unsaved changes were kept.';
                    }
                    return true;
                }

                let message = data.error || 'Save failed';
                if (data.code === 'EDIT_CONFLICT') {
                    message = window.i18n
                        ? i18n.t('editor.editConflict')
                        : 'The file changed on the server. Reopen it before saving.';
                } else if (data.code === 'EDIT_ENCODING_UNSUPPORTED' && window.i18n) {
                    message = this.encodingRefusalMessage(data);
                } else if (data.code === 'SMB_RECOVERY_REQUIRED') {
                    const leaves = Array.isArray(data.recovery_leaves)
                        ? data.recovery_leaves.join(', ')
                        : '';
                    message = (window.i18n
                        ? i18n.t('editor.recoveryRequired')
                        : 'Manual recovery is required. Preserve these files: {files}'
                    ).replace('{files}', leaves);
                }
                if (status) status.textContent = message;
                showNotification(message, 'error');
                return true;
            }
            return false;
        },

        encodingRefusalMessage(data) {
            const character = typeof data.character === 'string' ? data.character : '';
            const codePoint = character.codePointAt(0);
            const valid = codePoint !== undefined
                && String.fromCodePoint(codePoint) === character
                && Number.isSafeInteger(data.line) && data.line > 0;
            if (!valid) return i18n.t('editor.encodingUnsupported');
            const values = {
                line: String(data.line),
                character,
                codepoint: `U+${codePoint.toString(16).toUpperCase().padStart(4, '0')}`,
            };
            // Invisible and bidi control characters would hide or reorder the
            // message, so only their code point is shown.
            const key = /^[\p{Cf}\p{Zs}\p{Zl}\p{Zp}]$/u.test(character)
                ? 'editor.encodingUnsupportedCodepoint'
                : 'editor.encodingUnsupportedCharacter';
            return i18n.t(key)
                .replace(/\{(line|character|codepoint)\}/g, (_match, name) => values[name]);
        },

        renderPreviewPanels() {
            // Responses may prepare the preview while editing, but only the
            // current mode owns visibility. Cancel reveals the prepared panel.
            for (const id of ['previewLoading', 'previewError', 'previewBinary', 'previewImage', 'previewContent']) {
                document.getElementById(id)?.classList.toggle('hidden', this.editMode || id !== this._previewPanel);
            }
            document.getElementById('previewTruncated')?.classList.toggle('hidden',
                this.editMode || this._previewPanel !== 'previewContent' || !this._previewTruncated);
            document.getElementById('previewEditBtn')?.classList.toggle('hidden',
                this.editMode || this._previewPanel !== 'previewContent' || !this._previewEditable);
        },

        showLoading() {
            this._previewPanel = 'previewLoading';
            this._previewTruncated = false;
            this._previewEditable = false;
            this.renderPreviewPanels();
            if (!this.editMode) document.getElementById('fileEditor')?.classList.add('hidden');
        },

        hideLoading() {
            document.getElementById('previewLoading')?.classList.add('hidden');
        },

        showError(message) {
            document.getElementById('previewErrorMessage').textContent = message;
            this._previewPanel = 'previewError';
            this._previewEditable = false;
            this.renderPreviewPanels();
        },

        showBinary() {
            this._previewPanel = 'previewBinary';
            this._previewEditable = false;
            this.renderPreviewPanels();
        },

        showImage(url, size) {
            const imageElement = document.getElementById('previewImageElement');

            this._previewPanel = 'previewImage';
            this._previewEditable = false;
            this.renderPreviewPanels();
            document.getElementById('previewSize').textContent = this.formatFileSize(size);

            if (imageElement.src && imageElement.src.startsWith('blob:')) {
                URL.revokeObjectURL(imageElement.src);
            }

            imageElement.onload = () => {};
            const requestId = this.currentPreviewRequestId;
            imageElement.onerror = () => {
                if (this.currentPreviewRequestId !== requestId) return;
                this.showError('Failed to load image');
            };

            imageElement.src = url;
        },

        showContent(content, filename, truncated, readSize, totalSize) {
            const codeEl = document.getElementById('previewCode');
            const lineNumbersEl = document.getElementById('previewLineNumbers');

            this._previewPanel = 'previewContent';
            this._previewTruncated = Boolean(truncated);

            // Keep the raw content for an accurate copy; for display, drop a
            // single trailing newline so the file's terminator isn't rendered
            // (and numbered) as a spurious empty last line.
            this._previewFullContent = content;
            const copyButton = document.getElementById('previewCopyBtn');
            if (copyButton) copyButton.disabled = false;
            const display = content.replace(/\n$/, '');
            codeEl.textContent = display;

            const language = this.getLanguage(filename);
            const requestId = this.currentPreviewRequestId;
            // The hidden preview can be formatted while the separate editor is open.
            window.PreviewHighlight?.render(codeEl, language, () => (
                this.currentPreviewRequestId === requestId
                && this._previewFullContent === content
            ));

            const lineCount = display === '' ? 1 : display.split('\n').length;
            lineNumbersEl.innerHTML = Array.from({ length: lineCount }, (_, i) => i + 1).join('<br>');

            if (truncated) {
                document.getElementById('previewTruncatedSize').textContent = this.formatFileSize(readSize);
                document.getElementById('previewTotalSize').textContent = this.formatFileSize(totalSize);
            }
            this.renderPreviewPanels();
        },

        async copyToClipboard() {
            if (this._previewFullContent == null) return;
            try {
                await TerminalManager.writeTextToClipboard(this._previewFullContent);
                showNotification((window.i18n ? window.i18n.t('toast.copied') : 'Copied to clipboard'), 'success');
            } catch {
                showNotification((window.i18n ? window.i18n.t('toast.copyFailed') : 'Failed to copy'), 'error');
            }
        },

        downloadFile() {
            if (!this.currentSourceId || !this.currentPath) return;
            BinaryTransferClient.forSocket(socket).downloadFile(
                this.currentPath, this.currentSourceId
            );
        },

        // ---- Inline editor ----
        showEditButton() {
            this._previewEditable = true;
            this.renderPreviewPanels();
        },

        hideEditButton() {
            this._previewEditable = false;
            this.renderPreviewPanels();
        },

        showPreviewActions() {
            const copyButton = document.getElementById('previewCopyBtn');
            if (copyButton) copyButton.disabled = this._previewFullContent == null;
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
                if (this.dirty || this.pendingSaveContent != null) {
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
            this.resetEditReview();
            this.dirty = document.getElementById('editorContent')?.value !== this.editBaseline;
            const status = document.getElementById('editorStatus');
            if (status) {
                status.textContent = this.dirty
                    ? (window.i18n ? i18n.t('editor.unsavedChanges') : 'Unsaved changes') : '';
            }
        },

        enterEditMode() {
            if (this.editMode || !this.currentSourceId || !this.currentPath) return;
            const status = document.getElementById('editorStatus');
            if (status) status.textContent = '';
            this.currentEditRequestId = this.nextRequestId('edit');
            socket.emit('open_file_for_edit', {
                source_id: this.currentSourceId,
                path: this.currentPath,
                request_id: this.currentEditRequestId,
            });
        },

        openForEditing(sourceId, path, filename) {
            const previousRequest = this.currentPreviewRequestId;
            this.open(sourceId, path, filename);
            if (this.currentPreviewRequestId !== previousRequest
                    && this.currentSourceId === sourceId && this.currentPath === path) this.enterEditMode();
        },

        handleEditData(data) {
            // Ignore responses for a file the user has since navigated away from.
            if (!this.matchesResponse(data, this.currentEditRequestId)
                    || data.path !== this.currentPath) return;

            const textarea = document.getElementById('editorContent');
            if (!textarea) return;

            this.currentEditRequestId = null;
            this.editEncoding = data.encoding || 'utf-8';
            this.editNewline = data.newline || 'lf';
            this.editRevision = data.revision || null;
            textarea.value = data.content || '';
            this.editBaseline = textarea.value;
            this.editOriginalBytes = typeof data.original_bytes === 'string' ? data.original_bytes : null;
            const source = window.sftpFileManager?.buildSourceCatalog?.()
                .flatMap(group => group.items).find(item => item.sourceId === this.currentSourceId);
            this.editTarget = Object.freeze({
                sourceId: this.currentSourceId,
                path: this.currentPath,
                endpoint: data.endpoint || source?.endpoint || this.currentSourceId,
            });
            this.resetEditReview();

            this.editMode = true;
            this.renderPreviewPanels();
            document.getElementById('fileEditor')?.classList.remove('hidden');
            this.modal?.classList.add('editing');
            this.hidePreviewActions();

            this.dirty = false;
            const status = document.getElementById('editorStatus');
            if (status) status.textContent = '';
            this.attachBeforeUnload();
            textarea.focus();
        },

        handleEditError(data) {
            if (!this.matchesResponse(data, this.currentEditRequestId)) return;
            const msg = (data && data.error) ? data.error
                : (window.i18n ? i18n.t('editor.saveFailed') : 'Failed to open file');
            showNotification(msg, 'error');
        },

        clearPendingSave(preserveResponse = false) {
            clearTimeout(this.saveTimer);
            if (!preserveResponse) this.saveRequests.delete(this.currentSaveRequestId);
            this.saveTimer = null;
            this.pendingSaveContent = null;
            this.currentSaveRequestId = null;
        },

        interruptSave() {
            if (this.pendingSaveContent == null) return;
            // The write may already have completed remotely. Keep its identity
            // so a delayed acknowledgement can reconcile the revision.
            this.clearPendingSave(true);
            this.markDirty();
            this.setSaveOutcomeUnknown(true);
        },

        setSaveOutcomeUnknown(unknown) {
            this.saveOutcomeUnknown = unknown;
            for (const id of ['editorSaveBtn', 'editorCommitBtn']) {
                const button = document.getElementById(id);
                if (button) button.disabled = unknown;
            }
            for (const id of ['editorDraftBtn', 'editorReloadBtn']) {
                const button = document.getElementById(id);
                if (button) button.hidden = id === 'editorDraftBtn' ? false : !unknown;
            }
            if (unknown) {
                const message = window.i18n ? i18n.t('editor.saveOutcomeUnknown')
                    : 'The save result is unknown. Download your draft, then reopen and compare before saving again.';
                const status = document.getElementById('editorStatus');
                if (status) status.textContent = message;
                showNotification(message, 'warning');
            }
        },

        downloadDraft() {
            const text = document.getElementById('editorContent')?.value;
            if (typeof text !== 'string') return;
            const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }));
            const link = document.createElement('a');
            link.href = url;
            link.download = `${this.currentFilename || 'file'}.draft.txt`;
            link.click();
            setTimeout(() => URL.revokeObjectURL(url), 1000);
        },

        resetEditReview() {
            this.editReview = null;
            document.getElementById('editorReview')?.classList.add('hidden');
            document.getElementById('editorContent')?.classList.remove('hidden');
            const reviewButton = document.getElementById('editorSaveBtn');
            if (reviewButton) reviewButton.disabled = Boolean(this.saveOutcomeUnknown);
            for (const id of ['editorReviewOriginal', 'editorReviewEdited']) {
                const field = document.getElementById(id);
                if (field) field.value = '';
            }
        },

        dismissEditReview() {
            if (this.pendingSaveContent != null) return;
            this.resetEditReview();
            document.getElementById('editorContent')?.focus();
        },

        saveEdit() {
            if (this.saveOutcomeUnknown) return;
            if (!this.editMode || this.pendingSaveContent != null || !this.editTarget
                || this.editTarget.sourceId !== this.currentSourceId
                || this.editTarget.path !== this.currentPath || !this.editRevision) return;
            const content = document.getElementById('editorContent')?.value;
            if (typeof content !== 'string' || this.editBaseline == null) return;
            if (content.length > this.maxEditFileSize) {
                const status = document.getElementById('editorStatus');
                if (status) status.textContent = (window.i18n
                    ? i18n.t('editor.reviewTooLarge')
                    : 'File too large to review (maximum {size}).'
                ).replace('{size}', this.formatFileSize(this.maxEditFileSize));
                return;
            }
            const diff = window.FileEditDiff?.compare(this.editBaseline, content);
            if (!diff?.changed) return;
            this.editReview = Object.freeze({
                ...this.editTarget, content, revision: this.editRevision,
                encoding: this.editEncoding, newline: this.editNewline,
            });
            document.getElementById('editorReviewTarget').textContent = `${this.editTarget.endpoint}\n${this.editTarget.path}`;
            window.FileEditDiff.render(document.getElementById('editorReviewDiff'), diff);
            document.getElementById('editorReviewLimited')?.classList[diff.limited ? 'remove' : 'add']('hidden');
            document.getElementById('editorReviewOriginal').value = this.editBaseline;
            document.getElementById('editorReviewEdited').value = content;
            document.getElementById('editorContent')?.classList.add('hidden');
            document.getElementById('editorReview')?.classList.remove('hidden');
            const backup = document.getElementById('editorBackupBtn');
            if (backup) backup.disabled = this.editOriginalBytes == null;
            document.getElementById('editorCommitBtn')?.focus();
        },

        commitReviewedEdit() {
            this.saveReviewedEdit();
        },

        downloadOriginal() {
            if (this.editOriginalBytes == null || !this.editTarget) return;
            const decoded = atob(this.editOriginalBytes);
            const bytes = Uint8Array.from(decoded, character => character.charCodeAt(0));
            const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
            const link = document.createElement('a');
            link.href = url;
            link.download = `${this.currentFilename || 'file'}.original`;
            link.click();
            setTimeout(() => URL.revokeObjectURL(url), 1000);
        },

        saveReviewedEdit(replaceStrategy = null, saveChallenge = null) {
            if (this.saveOutcomeUnknown) return;
            if (!this.editMode || !this.currentSourceId || !this.currentPath) return;
            if (this.pendingSaveContent != null) return;
            const reviewed = this.editReview;
            const textarea = document.getElementById('editorContent');
            if (!reviewed || reviewed.sourceId !== this.currentSourceId
                || reviewed.path !== this.currentPath || reviewed.revision !== this.editRevision
                || reviewed.content !== textarea?.value || reviewed.encoding !== this.editEncoding
                || reviewed.newline !== this.editNewline) {
                this.resetEditReview();
                return;
            }
            if (socket.connected !== true) {
                showNotification(window.i18n ? i18n.t('editor.saveFailed') : 'Failed to save file', 'error');
                return;
            }
            const status = document.getElementById('editorStatus');
            if (status) status.textContent = window.i18n ? i18n.t('editor.saving') : 'Saving...';

            this.currentSaveRequestId = this.nextRequestId('save');
            const selectedStrategy = replaceStrategy || (
                this.recoverableReplaceSources.has(this.currentSourceId)
                    ? 'recoverable_swap'
                    : 'atomic'
            );
            const payload = {
                source_id: this.currentSourceId,
                path: this.currentPath,
                content: textarea.value,
                encoding: this.editEncoding,
                newline: this.editNewline,
                expected_revision: this.editRevision,
                replace_strategy: selectedStrategy,
                request_id: this.currentSaveRequestId,
            };
            this.pendingSaveContent = textarea.value;
            this.saveRequests.set(this.currentSaveRequestId, {
                content: textarea.value,
                sequence: this.requestSequence,
            });
            this.saveTimer = setTimeout(() => this.interruptSave(), 30000);
            if (typeof saveChallenge === 'string' && saveChallenge) {
                payload.save_challenge = saveChallenge;
            }
            socket.emit('save_file', payload);
        },

        handleFileSaved(data) {
            const saved = this.saveRequests.get(data?.request_id);
            if (!saved || !this.editMode || data.source_id !== this.currentSourceId
                    || data.path !== this.currentPath) return;
            const isCurrent = data.request_id === this.currentSaveRequestId;
            this.saveRequests.delete(data.request_id);
            if (isCurrent) this.clearPendingSave();
            if (saved.sequence <= this.lastSavedSequence) return;
            this.setSaveOutcomeUnknown(false);
            this.lastSavedSequence = saved.sequence;
            this.editRevision = data.revision || this.editRevision;
            this.editBaseline = saved.content;
            // Exact remote bytes must be read again after the baseline changes.
            this.editOriginalBytes = null;
            const backupButton = document.getElementById('editorBackupBtn');
            if (backupButton) backupButton.disabled = true;
            const keepEditing = !isCurrent
                || document.getElementById('editorContent')?.value !== saved.content;
            if (keepEditing) {
                this.markDirty();
                this.attachBeforeUnload();
            } else {
                this.dirty = false;
                this.detachBeforeUnload();
            }
            if (data.warning_code === 'SMB_RECOVERY_BACKUP_RETAINED') {
                const leaves = Array.isArray(data.recovery_leaves)
                    ? data.recovery_leaves.join(', ')
                    : '';
                const message = (window.i18n
                    ? i18n.t('editor.recoveryBackupRetained')
                    : 'File saved, but a recovery backup remains: {files}'
                ).replace('{files}', leaves);
                const status = document.getElementById('editorStatus');
                if (status) status.textContent = message;
                showNotification(message, 'warning');
                return;
            }
            if (keepEditing) return;
            showNotification(window.i18n ? i18n.t('editor.saved') : 'File saved', 'success');
            // Leave edit mode and reload the preview to reflect the saved file.
            this.exitEditMode();
            this.refresh();
        },

        cancelEdit() {
            if (this.dirty || this.pendingSaveContent != null) {
                const msg = window.i18n ? i18n.t('editor.unsavedConfirm') : 'Discard unsaved changes?';
                if (!window.confirm(msg)) return;
            }
            this.exitEditMode();
        },

        exitEditMode() {
            this.setSaveOutcomeUnknown(false);
            this.resetEditReview();
            this.clearPendingSave();
            this.saveRequests.clear();
            this.editMode = false;
            this.dirty = false;
            this.editRevision = null;
            this.editBaseline = null;
            this.editOriginalBytes = null;
            this.editTarget = null;
            this.detachBeforeUnload();
            document.getElementById('fileEditor')?.classList.add('hidden');
            this.modal?.classList.remove('editing');
            const status = document.getElementById('editorStatus');
            if (status) status.textContent = '';
            this.showPreviewActions();
            this.renderPreviewPanels();
        },

        refresh() {
            if (!this.currentSourceId || !this.currentPath) return;

            const filename = this.currentPath.split('/').pop();
            this.open(this.currentSourceId, this.currentPath, filename);
        },

        close() {
            if (this.editMode && (this.dirty || this.pendingSaveContent != null)) {
                const msg = window.i18n ? i18n.t('editor.unsavedConfirm') : 'Discard unsaved changes?';
                if (!window.confirm(msg)) return;
            }
            this.detachBeforeUnload();
            this.resetEditReview();
            this.editBaseline = null;
            this.editOriginalBytes = null;
            this.editTarget = null;
            this.editMode = false;
            this.dirty = false;
            document.getElementById('fileEditor')?.classList.add('hidden');
            this.modal?.classList.remove('editing');

            window.ModalManager.close(this.modal);
            this.currentSourceId = null;
            this.currentPath = null;
            this.currentFilename = null;
            this._previewFullContent = null;
            this.clearPendingSave();
            this.saveRequests.clear();
            this.currentPreviewRequestId = null;
            this.currentEditRequestId = null;
            this.currentSaveRequestId = null;

            const imgEl = document.getElementById('previewImageElement');
            if (imgEl && imgEl.src.startsWith('blob:')) {
                URL.revokeObjectURL(imgEl.src);
                imgEl.src = '';
            }
        }
    };

    window.FilePreview = FilePreview;
})();
