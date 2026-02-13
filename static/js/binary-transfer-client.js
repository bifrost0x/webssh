
class BinaryTransferClient {
    constructor(socket) {
        this.socket = socket;
        this.activeTransfers = new Map();
        this.eventListeners = new Map();
        this.transferQueue = [];

        this.setupSocketListeners();
    }

    generateId() {
        return `transfer_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    maxUploadSize = 100 * 1024 * 1024;

    validateFile(file) {
        if (file.size > this.maxUploadSize) {
            return `File too large (${(file.size / 1024 / 1024).toFixed(2)}MB). Maximum size is ${(this.maxUploadSize / 1024 / 1024)}MB.`;
        }

        if (file.size === 0) {
            return 'Cannot upload empty files.';
        }

        return null;
    }

    uploadFile(file, remotePath, sessionOrConnectionId) {
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

        const reader = new FileReader();

        reader.onload = (e) => {
            const arrayBuffer = e.target.result;

            const transfer = this.activeTransfers.get(transferId);
            if (transfer) {
                transfer.status = 'uploading';
            }

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

    uploadFiles(files, remotePath, sessionOrConnectionId) {
        const transferIds = [];

        Array.from(files).forEach(file => {
            const fileRemotePath = `${remotePath}/${file.name}`;
            const id = this.uploadFile(file, fileRemotePath, sessionOrConnectionId);
            transferIds.push(id);
        });

        return transferIds;
    }

    async uploadDirectory(directoryEntry, remotePath, sessionOrConnectionId) {
        const transferIds = [];

        const readEntries = (directoryReader) => {
            return new Promise((resolve, reject) => {
                directoryReader.readEntries(resolve, reject);
            });
        };

        const processEntry = async (entry, basePath) => {
            if (entry.isFile) {
                entry.file((file) => {
                    const filePath = `${basePath}/${file.name}`;
                    const id = this.uploadFile(file, filePath, sessionOrConnectionId);
                    transferIds.push(id);
                });
            } else if (entry.isDirectory) {
                const dirPath = `${basePath}/${entry.name}`;

                this.socket.emit('create_directory', {
                    session_id: sessionOrConnectionId,
                    remote_path: dirPath
                });

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

    downloadFile(remotePath, sessionOrConnectionId) {
        const transferId = this.generateId();
        const filename = remotePath.split('/').pop();

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

        this.socket.emit('download_file_binary', {
            transfer_id: transferId,
            session_id: sessionOrConnectionId,
            remote_path: remotePath
        });

        this.emit('start', { transferId, type: 'download', filename });

        return transferId;
    }

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

    getTransfer(transferId) {
        return this.activeTransfers.get(transferId) || null;
    }

    getAllTransfers() {
        return Array.from(this.activeTransfers.values());
    }

    setupSocketListeners() {
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

                setTimeout(() => {
                    this.activeTransfers.delete(transfer.id);
                }, 5000);
            }
        });

        this.socket.on('file_download_ready_binary', (data) => {
            const transfer = this.findTransferBySession(data.session_id, data.filename);
            if (transfer) {
                const blob = new Blob([data.file_data]);

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

                setTimeout(() => {
                    this.activeTransfers.delete(transfer.id);
                }, 5000);
            }
        });

        this.socket.on('error', (data) => {
            if (data.transfer_id) {
                this.handleError(data.transfer_id, data.error);
            }
        });
    }

    findTransferBySession(sessionId, filename) {
        for (const transfer of this.activeTransfers.values()) {
            if (transfer.sessionId === sessionId && transfer.filename === filename) {
                return transfer;
            }
        }
        return null;
    }

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

            setTimeout(() => {
                this.activeTransfers.delete(transferId);
            }, 10000);
        }
    }

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

if (typeof module !== 'undefined' && module.exports) {
    module.exports = BinaryTransferClient;
}
