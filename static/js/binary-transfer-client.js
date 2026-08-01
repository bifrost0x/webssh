class BinaryTransferClient {
    constructor(socket) {
        this.socket = socket;
        this.activeTransfers = new Map();
        this.eventListeners = new Map();
        this.setupSocketListeners();
    }

    generateId() {
        return `transfer_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    }

    prepare(direction, sessionId, remotePath, options = {}) {
        return new Promise((resolve, reject) => {
            this.socket.emit('prepare_transfer', {
                direction,
                session_id: sessionId,
                remote_path: remotePath,
                ...options,
            }, acknowledgement => {
                if (!acknowledgement || !acknowledgement.success) {
                    reject(new Error('Transfer unavailable'));
                    return;
                }
                resolve(acknowledgement);
            });
        });
    }

    csrfHeaders() {
        const token = document.querySelector('meta[name="csrf-token"]')?.content;
        return token ? { 'X-CSRFToken': token } : {};
    }

    uploadFile(file, remotePath, sessionId) {
        const localId = this.generateId();
        const transfer = {
            id: localId, type: 'upload', filename: file.name, size: file.size,
            transferred: 0, status: 'preparing', sessionId, remotePath,
            controller: new AbortController(),
        };
        this.activeTransfers.set(localId, transfer);
        this._upload(transfer, file);
        return localId;
    }

    async _upload(transfer, file) {
        try {
            const prepared = await this.prepare('upload', transfer.sessionId, transfer.remotePath);
            transfer.transferId = prepared.transfer_id;
            if (transfer.status === 'cancelled') {
                this.socket.emit('cancel_transfer', { transfer_id: prepared.transfer_id });
                return;
            }
            transfer.status = 'uploading';
            this.emit('start', { transferId: transfer.id, type: 'upload', filename: transfer.filename });
            const response = await fetch(prepared.url, {
                method: 'POST',
                body: file,
                credentials: 'same-origin',
                headers: this.csrfHeaders(),
                signal: transfer.controller.signal,
            });
            if (!response.ok) throw new Error('Transfer unavailable');
            this.complete(transfer);
        } catch (error) {
            if (transfer.status !== 'cancelled') this.handleError(transfer.id, 'Transfer unavailable');
        }
    }

    downloadFile(remotePath, sessionId) {
        const localId = this.generateId();
        const filename = remotePath.split('/').pop() || 'download';
        const transfer = {
            id: localId, type: 'download', filename, transferred: 0,
            status: 'preparing', sessionId, remotePath,
        };
        this.activeTransfers.set(localId, transfer);
        this._download(transfer);
        return localId;
    }

    downloadFolder(remotePath, sessionId) {
        const localId = this.generateId();
        const folder = remotePath.replace(/\/$/, '').split('/').pop() || 'download';
        const transfer = {
            id: localId, type: 'download', filename: `${folder}.zip`, transferred: 0,
            status: 'preparing', sessionId, remotePath, archive: true,
        };
        this.activeTransfers.set(localId, transfer);
        this._download(transfer);
        return localId;
    }

    downloadFileToWritable(remotePath, sessionId, sinkFactory) {
        const localId = this.generateId();
        const filename = remotePath.split('/').pop() || 'download';
        const transfer = {
            id: localId, type: 'download', filename, transferred: 0,
            status: 'preparing', sessionId, remotePath,
            controller: new AbortController(), writableDestination: true,
        };
        this.activeTransfers.set(localId, transfer);
        return {
            id: localId,
            done: this._downloadToWritable(transfer, sinkFactory),
        };
    }

    async _download(transfer) {
        try {
            const prepared = await this.prepare(
                'download', transfer.sessionId, transfer.remotePath,
                transfer.archive ? { archive: true } : {},
            );
            transfer.transferId = prepared.transfer_id;
            if (transfer.status === 'cancelled') {
                this.socket.emit('cancel_transfer', { transfer_id: prepared.transfer_id });
                return;
            }
            transfer.status = 'downloading';
            this.emit('start', { transferId: transfer.id, type: 'download', filename: transfer.filename });
            // Native navigation preserves browser save semantics and does not
            // collect a large response in JS memory. Progress comes from the
            // user-room Socket.IO control event, not response.blob().
            const anchor = document.createElement('a');
            anchor.href = prepared.url;
            anchor.download = '';
            anchor.style.display = 'none';
            document.body.appendChild(anchor);
            anchor.click();
            anchor.remove();
        } catch (_error) {
            this.handleError(transfer.id, 'Transfer unavailable');
        }
    }

    async _downloadToWritable(transfer, sinkFactory) {
        let writable;
        try {
            const prepared = await this.prepare(
                'download', transfer.sessionId, transfer.remotePath,
            );
            transfer.transferId = prepared.transfer_id;
            if (transfer.status === 'cancelled') {
                this.socket.emit('cancel_transfer', { transfer_id: prepared.transfer_id });
                return false;
            }
            transfer.status = 'downloading';
            this.emit('start', {
                transferId: transfer.id,
                type: 'download',
                filename: transfer.filename,
            });
            const response = await fetch(prepared.url, {
                credentials: 'same-origin',
                signal: transfer.controller.signal,
            });
            if (!response.ok || !response.body) {
                throw new Error('Transfer unavailable');
            }
            writable = await sinkFactory();
            await response.body.pipeTo(
                writable,
                { signal: transfer.controller.signal },
            );
            if (transfer.status === 'cancelled') return false;
            this.complete(transfer);
            return true;
        } catch (error) {
            try {
                await writable?.abort?.();
            } catch (_abortError) {
                // The stream may already have been aborted by pipeTo().
            }
            if (transfer.status === 'cancelled') return false;
            transfer.controller.abort();
            if (transfer.transferId && !transfer.serverFinished) {
                this.socket.emit('cancel_transfer', {
                    transfer_id: transfer.transferId,
                });
            }
            this.handleError(transfer.id, 'Transfer unavailable');
            throw error;
        }
    }

    cancelTransfer(localId) {
        const transfer = this.activeTransfers.get(localId);
        if (!transfer) return;
        transfer.status = 'cancelled';
        transfer.controller?.abort();
        if (transfer.transferId) {
            this.socket.emit('cancel_transfer', { transfer_id: transfer.transferId });
        }
        this.emit('cancel', { transferId: localId });
        this.activeTransfers.delete(localId);
    }

    setupSocketListeners() {
        this.socket.on('transfer_progress', data => {
            for (const transfer of this.activeTransfers.values()) {
                if (transfer.transferId !== data.transfer_id) continue;
                transfer.transferred = data.transferred;
                transfer.total = data.total;
                transfer.percent = data.total ? Math.floor((data.transferred / data.total) * 100) : 0;
                this.emit('progress', { transferId: transfer.id, ...data, percent: transfer.percent });
            }
        });
        this.socket.on('transfer_finished', data => {
            for (const transfer of this.activeTransfers.values()) {
                if (transfer.transferId !== data.transfer_id) continue;
                if (
                    transfer.writableDestination
                    && data.status === 'completed'
                ) {
                    transfer.serverFinished = true;
                    continue;
                }
                if (data.status === 'completed') this.complete(transfer);
                else if (data.status !== 'cancelled') {
                    transfer.controller?.abort();
                    this.handleError(transfer.id, 'Transfer unavailable');
                } else {
                    transfer.status = 'cancelled';
                    transfer.controller?.abort();
                    this.emit('cancel', { transferId: transfer.id });
                }
                this.activeTransfers.delete(transfer.id);
            }
        });
    }

    complete(transfer) {
        transfer.status = 'completed';
        transfer.percent = 100;
        this.emit('complete', { transferId: transfer.id, type: transfer.type, filename: transfer.filename });
        this.activeTransfers.delete(transfer.id);
    }

    handleError(transferId, error) {
        const transfer = this.activeTransfers.get(transferId);
        if (!transfer) return;
        transfer.status = 'error';
        transfer.error = error;
        this.emit('error', { transferId, filename: transfer.filename, error });
        this.activeTransfers.delete(transferId);
    }

    on(event, callback) {
        if (!this.eventListeners.has(event)) this.eventListeners.set(event, []);
        this.eventListeners.get(event).push(callback);
    }

    emit(event, data) {
        for (const callback of this.eventListeners.get(event) || []) {
            try {
                callback(data);
            } catch (error) {
                console.error(`Transfer listener failed: ${error.message}`);
            }
        }
    }
}

if (typeof window !== 'undefined') window.BinaryTransferClient = BinaryTransferClient;
if (typeof module !== 'undefined' && module.exports) module.exports = BinaryTransferClient;
