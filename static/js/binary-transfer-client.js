/**
 * Binary Transfer Client
 *
 * Handles efficient binary file transfers over WebSocket without base64 encoding.
 * Provides 33% reduction in transfer size compared to base64.
 *
 * Features:
 * - Direct binary streaming via WebSocket
 * - Progress tracking
 * - Multiple concurrent transfers
 * - Transfer queue management
 * - Pause/resume capability (future enhancement)
 *
 * Usage:
 * const client = new BinaryTransferClient(socket);
 * const transferId = client.uploadFile(file, '/remote/path', sessionId);
 * client.on('progress', (data) => console.log(data.percent));
 */

class BinaryTransferClient {
    constructor(socket) {
        this.socket = socket;
        this.activeTransfers = new Map();
        this.eventListeners = new Map();
        this.transferQueue = [];

        this.setupSocketListeners();
    }

    /**
     * Generate unique transfer ID
     */
    generateId() {
        return `transfer_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    /**
     * SECURITY: Maximum upload size (100MB default, matches server config)
     */
    maxUploadSize = 100 * 1024 * 1024;

    /**
     * Validate file before upload
     * @param {File} file - File to validate
     * @returns {string|null} Error message or null if valid
     */
    validateFile(file) {
        // Check file size
        if (file.size > this.maxUploadSize) {
            return `File too large (${(file.size / 1024 / 1024).toFixed(2)}MB). Maximum size is ${(this.maxUploadSize / 1024 / 1024)}MB.`;
        }

        // Check for empty files
        if (file.size === 0) {
            return 'Cannot upload empty files.';
        }

        return null;  // Valid
    }

    /**
     * Upload file using binary WebSocket transfer
     *
     * @param {File} file - File object to upload
     * @param {string} remotePath - Target path on remote server
     * @param {string} sessionOrConnectionId - Session ID or temporary connection ID
     * @returns {string} Transfer ID
     */
    uploadFile(file, remotePath, sessionOrConnectionId) {
        // SECURITY: Validate file before upload
        const validationError = this.validateFile(file);
        if (validationError) {
            const errorId = this.generateId();
            this.emit('error', { transferId: errorId, error: validationError });
            if (window.showNotification) {
                window.showNotification(validationError, 'error');
            }
            return null;
        }

        const transferId = this.generateId();

        // Store transfer metadata
        this.activeTransfers.set(transferId, {
            id: transferId,
            type: 'upload',
            filename: file.name,
            size: file.size,
            transferred: 0,
            percent: 0,
            status: 'pending',
            sessionId: sessionOrConnectionId,
            remotePath: remotePath
        });

        // Read file as ArrayBuffer
        const reader = new FileReader();

        reader.onload = (e) => {
            const arrayBuffer = e.target.result;

            // Update status
            const transfer = this.activeTransfers.get(transferId);
            if (transfer) {
                transfer.status = 'uploading';
            }

            // Send binary data via WebSocket
            this.socket.emit('upload_file_binary', {
                transfer_id: transferId,
                session_id: sessionOrConnectionId,
                filename: file.name,
                remote_path: remotePath,
                file_data: arrayBuffer
            });

            this.emit('start', { transferId, type: 'upload', filename: file.name });
        };

        reader.onerror = () => {
            this.handleError(transferId, 'Failed to read file');
        };

        reader.readAsArrayBuffer(file);

        return transferId;
    }

    /**
     * Upload multiple files
     *
     * @param {FileList|Array} files - Files to upload
     * @param {string} remotePath - Target directory on remote server
     * @param {string} sessionOrConnectionId - Session ID or connection ID
     * @returns {Array} Array of transfer IDs
     */
    uploadFiles(files, remotePath, sessionOrConnectionId) {
        const transferIds = [];

        Array.from(files).forEach(file => {
            const fileRemotePath = `${remotePath}/${file.name}`;
            const id = this.uploadFile(file, fileRemotePath, sessionOrConnectionId);
            transferIds.push(id);
        });

        return transferIds;
    }

    /**
     * Upload folder recursively (using FileSystem API)
     *
     * @param {FileSystemDirectoryEntry} directoryEntry - Directory entry
     * @param {string} remotePath - Base remote path
     * @param {string} sessionOrConnectionId - Session ID or connection ID
     * @returns {Promise<Array>} Promise resolving to array of transfer IDs
     */
    async uploadDirectory(directoryEntry, remotePath, sessionOrConnectionId) {
        const transferIds = [];

        const readEntries = (directoryReader) => {
            return new Promise((resolve, reject) => {
                directoryReader.readEntries(resolve, reject);
            });
        };

        const processEntry = async (entry, basePath) => {
            if (entry.isFile) {
                // Get file from entry
                entry.file((file) => {
                    const filePath = `${basePath}/${file.name}`;
                    const id = this.uploadFile(file, filePath, sessionOrConnectionId);
                    transferIds.push(id);
                });
            } else if (entry.isDirectory) {
                // Create directory on remote (would need backend support)
                const dirPath = `${basePath}/${entry.name}`;

                // Emit create directory event
                this.socket.emit('create_directory', {
                    session_id: sessionOrConnectionId,
                    remote_path: dirPath
                });

                // Process directory contents
                const reader = entry.createReader();
                const entries = await readEntries(reader);

                for (const subEntry of entries) {
                    await processEntry(subEntry, dirPath);
                }
            }
        };

        await processEntry(directoryEntry, remotePath);

        return transferIds;
    }

    /**
     * Download file using binary transfer
     *
     * @param {string} remotePath - Path to file on remote server
     * @param {string} sessionOrConnectionId - Session ID or connection ID
     * @returns {string} Transfer ID
     */
    downloadFile(remotePath, sessionOrConnectionId) {
        const transferId = this.generateId();
        const filename = remotePath.split('/').pop();

        // Store transfer metadata
        this.activeTransfers.set(transferId, {
            id: transferId,
            type: 'download',
            filename: filename,
            transferred: 0,
            percent: 0,
            status: 'downloading',
            sessionId: sessionOrConnectionId,
            remotePath: remotePath
        });

        // Request download
        this.socket.emit('download_file_binary', {
            transfer_id: transferId,
            session_id: sessionOrConnectionId,
            remote_path: remotePath
        });

        this.emit('start', { transferId, type: 'download', filename });

        return transferId;
    }

    /**
     * Cancel an active transfer
     *
     * @param {string} transferId - Transfer ID to cancel
     */
    cancelTransfer(transferId) {
        const transfer = this.activeTransfers.get(transferId);
        if (!transfer) return;

        transfer.status = 'cancelled';

        this.socket.emit('cancel_transfer', {
            transfer_id: transferId,
            session_id: transfer.sessionId
        });

        this.emit('cancel', { transferId });
        this.activeTransfers.delete(transferId);
    }

    /**
     * Get transfer status
     *
     * @param {string} transferId - Transfer ID
     * @returns {Object|null} Transfer status or null
     */
    getTransfer(transferId) {
        return this.activeTransfers.get(transferId) || null;
    }

    /**
     * Get all active transfers
     *
     * @returns {Array} Array of transfer objects
     */
    getAllTransfers() {
        return Array.from(this.activeTransfers.values());
    }

    /**
     * Setup Socket.IO event listeners
     */
    setupSocketListeners() {
        // Progress updates
        this.socket.on('file_progress', (data) => {
            const transfer = this.findTransferBySession(data.session_id, data.filename);
            if (transfer) {
                transfer.transferred = data.transferred;
                transfer.percent = data.percent;

                this.emit('progress', {
                    transferId: transfer.id,
                    filename: data.filename,
                    transferred: data.transferred,
                    total: data.total,
                    percent: data.percent
                });
            }
        });

        // Upload complete
        this.socket.on('file_complete', (data) => {
            const transfer = this.findTransferBySession(data.session_id, data.filename);
            if (transfer) {
                transfer.status = 'completed';
                transfer.percent = 100;

                this.emit('complete', {
                    transferId: transfer.id,
                    type: data.type,
                    filename: data.filename
                });

                // Remove from active transfers after a delay
                setTimeout(() => {
                    this.activeTransfers.delete(transfer.id);
                }, 5000);
            }
        });

        // Download ready (binary data received)
        this.socket.on('file_download_ready_binary', (data) => {
            const transfer = this.findTransferBySession(data.session_id, data.filename);
            if (transfer) {
                // Create blob from binary data
                const blob = new Blob([data.file_data]);

                // Trigger download
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = data.filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);

                transfer.status = 'completed';
                transfer.percent = 100;

                this.emit('complete', {
                    transferId: transfer.id,
                    type: 'download',
                    filename: data.filename
                });

                // Remove from active transfers
                setTimeout(() => {
                    this.activeTransfers.delete(transfer.id);
                }, 5000);
            }
        });

        // Error handling
        this.socket.on('error', (data) => {
            if (data.transfer_id) {
                this.handleError(data.transfer_id, data.error);
            }
        });
    }

    /**
     * Find transfer by session ID and filename
     *
     * @param {string} sessionId - Session ID
     * @param {string} filename - Filename
     * @returns {Object|null} Transfer object or null
     */
    findTransferBySession(sessionId, filename) {
        for (const transfer of this.activeTransfers.values()) {
            if (transfer.sessionId === sessionId && transfer.filename === filename) {
                return transfer;
            }
        }
        return null;
    }

    /**
     * Handle transfer error
     *
     * @param {string} transferId - Transfer ID
     * @param {string} errorMessage - Error message
     */
    handleError(transferId, errorMessage) {
        const transfer = this.activeTransfers.get(transferId);
        if (transfer) {
            transfer.status = 'error';
            transfer.error = errorMessage;

            this.emit('error', {
                transferId,
                filename: transfer.filename,
                error: errorMessage
            });

            // Remove from active transfers after delay
            setTimeout(() => {
                this.activeTransfers.delete(transferId);
            }, 10000);
        }
    }

    /**
     * Event emitter methods
     */
    on(event, callback) {
        if (!this.eventListeners.has(event)) {
            this.eventListeners.set(event, []);
        }
        this.eventListeners.get(event).push(callback);
    }

    off(event, callback) {
        if (!this.eventListeners.has(event)) return;

        const listeners = this.eventListeners.get(event);
        const index = listeners.indexOf(callback);
        if (index > -1) {
            listeners.splice(index, 1);
        }
    }

    emit(event, data) {
        if (!this.eventListeners.has(event)) return;

        this.eventListeners.get(event).forEach(callback => {
            try {
                callback(data);
            } catch (error) {
                console.error(`Error in ${event} listener:`, error);
            }
        });
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = BinaryTransferClient;
}
