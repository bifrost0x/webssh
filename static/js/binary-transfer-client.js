class BinaryTransferClient {
    static forSocket(socket) {
        if (!socket || (typeof socket !== 'object' && typeof socket !== 'function')) {
            throw new TypeError('A Socket.IO client is required');
        }
        this.socketClients ||= new WeakMap();
        if (!this.socketClients.has(socket)) {
            this.socketClients.set(socket, new this(socket));
        }
        return this.socketClients.get(socket);
    }

    constructor(socket) {
        this.socket = socket;
        this.activeTransfers = new Map();
        this.eventListeners = new Map();
        this.operationQueue = [];
        this.activeOperation = null;
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

    createTransfer(properties, withDone = false) {
        const transfer = {
            id: this.generateId(),
            transferred: 0,
            status: 'queued',
            terminalized: false,
            slotReleased: false,
            prepareStarted: false,
            ...properties,
        };
        if (withDone) {
            transfer.done = new Promise((resolve, reject) => {
                transfer.resolveDone = resolve;
                transfer.rejectDone = reject;
            });
        }
        this.activeTransfers.set(transfer.id, transfer);
        return transfer;
    }

    enqueue(transfer, operation) {
        transfer.operation = operation;
        this.operationQueue.push(transfer);
        this.drainQueue();
    }

    drainQueue() {
        if (this.activeOperation) return;
        while (this.operationQueue.length > 0) {
            const transfer = this.operationQueue.shift();
            if (transfer.terminalized) {
                this.releaseSlot(transfer);
                continue;
            }
            this.activeOperation = transfer;
            Promise.resolve()
                .then(() => transfer.operation())
                .catch(error => {
                    if (!transfer.terminalized) this.failOperation(transfer, error);
                });
            return;
        }
    }

    uploadFile(file, remotePath, sessionId) {
        const transfer = this.createTransfer({
            type: 'upload',
            filename: file.name,
            size: file.size,
            sessionId,
            remotePath,
            controller: new AbortController(),
        });
        this.enqueue(transfer, () => this.upload(transfer, file));
        return transfer.id;
    }

    async upload(transfer, file) {
        if (transfer.terminalized) {
            this.releaseSlot(transfer);
            return;
        }
        try {
            transfer.status = 'preparing';
            transfer.prepareStarted = true;
            const prepared = await this.prepare(
                'upload', transfer.sessionId, transfer.remotePath,
            );
            transfer.transferId = prepared.transfer_id;
            if (transfer.terminalized) {
                this.cancelPreparedTransfer(transfer);
                return;
            }
            transfer.status = 'uploading';
            this.emit('start', {
                transferId: transfer.id,
                type: 'upload',
                filename: transfer.filename,
            });
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
            if (transfer.terminalized) {
                if (!transfer.transferId) this.releaseSlot(transfer);
                return;
            }
            this.failOperation(transfer, error);
        }
    }

    downloadFile(remotePath, sessionId) {
        const filename = remotePath.split('/').pop() || 'download';
        const transfer = this.createTransfer({
            type: 'download',
            filename,
            sessionId,
            remotePath,
        });
        this.enqueue(transfer, () => this.download(transfer));
        return transfer.id;
    }

    downloadFolder(remotePath, sessionId) {
        const folder = remotePath.replace(/\/$/, '').split('/').pop() || 'download';
        const transfer = this.createTransfer({
            type: 'download',
            filename: `${folder}.zip`,
            sessionId,
            remotePath,
            archive: true,
        });
        this.enqueue(transfer, () => this.download(transfer));
        return transfer.id;
    }

    downloadFileToWritable(remotePath, sessionId, sinkFactory) {
        const filename = remotePath.split('/').pop() || 'download';
        const transfer = this.createTransfer({
            type: 'download',
            filename,
            sessionId,
            remotePath,
            controller: new AbortController(),
            writableDestination: true,
        }, true);
        this.enqueue(transfer, () => this.downloadToWritable(transfer, sinkFactory));
        return { id: transfer.id, done: transfer.done };
    }

    async download(transfer) {
        if (transfer.terminalized) {
            this.releaseSlot(transfer);
            return;
        }
        try {
            transfer.status = 'preparing';
            transfer.prepareStarted = true;
            const prepared = await this.prepare(
                'download', transfer.sessionId, transfer.remotePath,
                transfer.archive ? { archive: true } : {},
            );
            transfer.transferId = prepared.transfer_id;
            if (transfer.terminalized) {
                this.cancelPreparedTransfer(transfer);
                return;
            }
            transfer.status = 'downloading';
            this.emit('start', {
                transferId: transfer.id,
                type: 'download',
                filename: transfer.filename,
            });
            // Native navigation keeps the response out of JS memory. The
            // transfer_finished control event terminalizes this queue slot.
            const anchor = document.createElement('a');
            anchor.href = prepared.url;
            anchor.download = '';
            anchor.style.display = 'none';
            document.body.appendChild(anchor);
            anchor.click();
            anchor.remove();
        } catch (error) {
            if (transfer.terminalized) {
                if (!transfer.transferId) this.releaseSlot(transfer);
                return;
            }
            this.failOperation(transfer, error);
        }
    }

    async downloadToWritable(transfer, sinkFactory) {
        let writable;
        if (transfer.terminalized) {
            this.releaseSlot(transfer);
            return;
        }
        try {
            transfer.status = 'preparing';
            transfer.prepareStarted = true;
            const prepared = await this.prepare(
                'download', transfer.sessionId, transfer.remotePath,
            );
            transfer.transferId = prepared.transfer_id;
            if (transfer.terminalized) {
                this.cancelPreparedTransfer(transfer);
                return;
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
            await response.body.pipeTo(writable, {
                signal: transfer.controller.signal,
            });
            if (!transfer.terminalized) this.complete(transfer);
        } catch (error) {
            try {
                await writable?.abort?.();
            } catch (_abortError) {
                // pipeTo() may already have aborted the destination.
            }
            if (transfer.terminalized) {
                if (!transfer.transferId) this.releaseSlot(transfer);
                return;
            }
            transfer.controller.abort();
            this.failOperation(transfer, error);
        }
    }

    cancelTransfer(localId) {
        const transfer = this.activeTransfers.get(localId);
        if (!transfer || transfer.terminalized) return;
        const deferRelease = (
            transfer === this.activeOperation
            && transfer.prepareStarted
            && !transfer.serverFinished
        );
        transfer.controller?.abort();
        this.finalize(transfer, 'cancelled', { deferRelease });
        if (deferRelease && transfer.transferId) {
            this.cancelPreparedTransfer(transfer);
        }
    }

    cancelPreparedTransfer(transfer) {
        if (!transfer.transferId) {
            this.releaseSlot(transfer);
            return;
        }
        if (transfer.cancelSent) return;
        transfer.cancelSent = true;
        try {
            this.socket.emit('cancel_transfer',
                { transfer_id: transfer.transferId },
                () => this.releaseSlot(transfer),
            );
        } catch (_error) {
            this.releaseSlot(transfer);
        }
    }

    failOperation(transfer, error) {
        const deferRelease = Boolean(
            transfer === this.activeOperation
            && transfer.transferId
            && !transfer.serverFinished,
        );
        this.finalize(transfer, 'error', {
            error: 'Transfer unavailable',
            rejection: error,
            deferRelease,
        });
        if (deferRelease) this.cancelPreparedTransfer(transfer);
    }

    setupSocketListeners() {
        this.socket.on('transfer_progress', data => {
            for (const transfer of this.activeTransfers.values()) {
                if (transfer.transferId !== data.transfer_id || transfer.terminalized) continue;
                transfer.transferred = data.transferred;
                transfer.total = data.total;
                transfer.percent = data.total
                    ? Math.floor((data.transferred / data.total) * 100)
                    : 0;
                this.emit('progress', {
                    transferId: transfer.id,
                    ...data,
                    percent: transfer.percent,
                });
            }
        });
        this.socket.on('transfer_finished', data => {
            for (const transfer of this.activeTransfers.values()) {
                if (transfer.transferId !== data.transfer_id) continue;
                if (transfer.terminalized) {
                    this.releaseSlot(transfer);
                    return;
                }
                if (
                    transfer.writableDestination
                    && data.status === 'completed'
                ) {
                    transfer.serverFinished = true;
                    return;
                }
                if (data.status === 'completed') {
                    this.complete(transfer);
                } else if (data.status === 'cancelled') {
                    transfer.controller?.abort();
                    this.finalize(transfer, 'cancelled');
                } else {
                    transfer.controller?.abort();
                    this.finalize(transfer, 'error', {
                        error: 'Transfer unavailable',
                        rejection: new Error('Transfer unavailable'),
                    });
                }
                return;
            }
        });
    }

    complete(transfer) {
        this.finalize(transfer, 'completed');
    }

    finalize(transfer, status, options = {}) {
        if (transfer.terminalized) return false;
        transfer.terminalized = true;
        transfer.status = status;

        if (status === 'completed') {
            transfer.percent = 100;
            this.emit('complete', {
                transferId: transfer.id,
                type: transfer.type,
                filename: transfer.filename,
            });
            transfer.resolveDone?.(true);
        } else if (status === 'cancelled') {
            this.emit('cancel', { transferId: transfer.id });
            transfer.resolveDone?.(false);
        } else {
            transfer.error = options.error;
            this.emit('error', {
                transferId: transfer.id,
                filename: transfer.filename,
                error: options.error,
            });
            transfer.rejectDone?.(
                options.rejection instanceof Error
                    ? options.rejection
                    : new Error(options.error || 'Transfer unavailable'),
            );
        }

        if (!options.deferRelease) this.releaseSlot(transfer);
        return true;
    }

    releaseSlot(transfer) {
        if (transfer.slotReleased) return;
        transfer.slotReleased = true;
        this.activeTransfers.delete(transfer.id);
        this.operationQueue = this.operationQueue.filter(item => item !== transfer);
        if (this.activeOperation === transfer) this.activeOperation = null;
        Promise.resolve().then(() => this.drainQueue());
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
